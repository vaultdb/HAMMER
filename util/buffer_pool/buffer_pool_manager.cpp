#include "buffer_pool_manager.h"
#include <query_table/packed_column_table.h>
#include <query_table/buffered_column_table.h>
#include "util/utilities.h"

using namespace  vaultdb;

#if  __has_include("emp-sh2pc/emp-sh2pc.h") || __has_include("emp-zk/emp-zk.h")
#include "emp-sh2pc/emp-sh2pc.h"
#else



void BufferPoolManager::loadPage(PageId &pid) {
    if(lru_k_enabled_) {
        loadPageWithLRUK(pid);
        return;
    }

    if(position_map_.find(pid) != position_map_.end()) {
        ++hits_;
        return;
    }

    int target_slot = evictPage();
    getPage(pid, target_slot);

    ++misses_;


}

void BufferPoolManager::loadPageWithLRUK(vaultdb::PageId &pid) {
    lru_k_time_cursor_++;

    if(position_map_.find(pid) != position_map_.end()) {
        ++hits_;

        // push the current time to the back of the lastKAccess list
        if(position_map_.at(pid).last_k_accesses_.size() == K) {
            position_map_[pid].last_k_accesses_.erase(position_map_[pid].last_k_accesses_.begin());
        }

        position_map_[pid].last_k_accesses_.push_back(lru_k_time_cursor_);

        lru_k_min_heap_.emplace(pid, position_map_[pid].last_k_accesses_.front());

        return;
    }


    int target_slot = evictPageWithLRUK();
    getPage(pid, target_slot);

    ++misses_;

    position_map_[pid].last_k_accesses_.push_back(lru_k_time_cursor_);

    lru_k_min_heap_.emplace(pid, position_map_[pid].last_k_accesses_.front());
}


// greedily evict first unpinned page in the queue
// returns the newly-opened slot in the buffer pool
int BufferPoolManager::evictPage() {
    PositionMapEntry pos;
    //  uninitialized slot
    if(reverse_position_map_.find(clock_hand_position_) == reverse_position_map_.end())  {
        int slot = clock_hand_position_;
        clock_hand_position_ = (clock_hand_position_ + 1) % page_cnt_;
        return slot;
    };

    int clock_hand_starting_pos = clock_hand_position_;

    PageId pid = reverse_position_map_[clock_hand_position_];
    pos = position_map_.at(pid);

    // first unpinned page
    while(pos.pinned_) {
        clock_hand_position_ = (clock_hand_position_ + 1) % page_cnt_;
        pid = reverse_position_map_[clock_hand_position_];
        pos = position_map_.at(pid);
        if(clock_hand_position_ == clock_hand_starting_pos) {
            // if we have gone through the whole buffer pool and all pages are pinned, then we have a problem
            // we should never have all pages pinned
            throw std::runtime_error("Buffer pool has no unpinned pages!");
        }
    }



    flushPage(pid);

    // remove it from the position map even if it is not dirty
    position_map_.erase(pid);
    reverse_position_map_.erase(pos.slot_id_);

    // increment clock hand one more time for next round
    clock_hand_position_ = (clock_hand_position_ + 1) % page_cnt_;
    return pos.slot_id_;
}

int BufferPoolManager::evictPageWithLRUK() {
    // check if the unpacked buffer pool is full
    if(reverse_position_map_.find(clock_hand_position_) == reverse_position_map_.end())  {
        int slot = clock_hand_position_;
        clock_hand_position_ = (clock_hand_position_ + 1) % page_cnt_;
        return slot;
    }

    // If the pool is full, evict a page by LRU-K
//    int min_kth_access = INT_MAX;
//    int min_slot = -1;
//    PageId min_pid;
//
//    for(auto &entry : position_map_) {
//        if(!entry.second.pinned_) {
//            assert(entry.second.last_k_accesses_.size() <= K);
//            int kth_access = entry.second.last_k_accesses_.front();
//
//            if(kth_access < min_kth_access) {
//                min_kth_access = kth_access;
//                min_slot = entry.second.slot_id_;
//                min_pid = entry.first;
//            }
//        }
//    }

    // Use min heap to replace loop.
    PageId min_pid;
    int min_slot = -1;

    while(!lru_k_min_heap_.empty()) {
        pair<PageId, int> top = lru_k_min_heap_.top();
        lru_k_min_heap_.pop();

        // break the loop if:
        // 1. the page is not pinned
        // 2. the page is in the position map
        // 3. the last k access counter matches.
        if((!position_map_[min_pid].pinned_) && (position_map_.find(top.first) != position_map_.end()) && (position_map_[top.first].last_k_accesses_.front() == top.second)) {
            min_pid = top.first;
            min_slot = position_map_[min_pid].slot_id_;

            break;
        }
    }

    PositionMapEntry pos = position_map_[min_pid];
    assert(pos.slot_id_ == min_slot);

    if (pos.dirty_ && table_catalog_.find(min_pid.table_id_) != table_catalog_.end()) {
            flushPage(min_pid);
    }

    position_map_.erase(min_pid);
    reverse_position_map_.erase(pos.slot_id_);

    return min_slot;
}

// makes a deep copy of src_pid at dst_pid
void BufferPoolManager::clonePage(PageId &src_pid, PageId &dst_pid) {
    // if src page is already in cache, copy it to dst page in buffer pool
    // mark dst_page as dirty
    // ordinarily wouldn't allow copy of dirty writes, but b/c this is a read-only workload, we allow it
    if(position_map_.find(src_pid) != position_map_.end()
       && position_map_.at(src_pid).dirty_) {
        emp::Bit *src_page = buffer_pool_.data() + position_map_.at(src_pid).slot_id_ * page_size_bits_;
        loadPage(dst_pid); // make sure dst page is loaded (if not already in buffer pool)
        emp::Bit *dst_page = buffer_pool_.data() + position_map_.at(dst_pid).slot_id_ * page_size_bits_;
        memcpy(dst_page, src_page, page_size_bits_);
        position_map_.at(dst_pid).dirty_ = true;
    }
    else {
        if(SystemConfiguration::getInstance().storageModel() == StorageModel::PACKED_COLUMN_STORE) {
            PackedColumnTable *src_table = (PackedColumnTable *) table_catalog_[src_pid.table_id_];
            PackedColumnTable *dst_table = (PackedColumnTable *) table_catalog_[dst_pid.table_id_];

            OMPCPackedWire src = src_table->readPackedWire(src_pid);
            dst_table->writePackedWire(dst_pid, src);
        }
        else {
            assert(SystemConfiguration::getInstance().storageModel() == StorageModel::COLUMN_STORE);
//            auto src = getPagePtr(src_pid);
//            auto dst = getPagePtr(dst_pid);
//            memcpy(dst, src, page_size_bits_);
//            position_map_.at(dst_pid).dirty_ = true;

            BufferedColumnTable *src_table = (BufferedColumnTable *) table_catalog_[src_pid.table_id_];
            BufferedColumnTable *dst_table = (BufferedColumnTable *) table_catalog_[dst_pid.table_id_];

            std::vector<emp::Bit> src_page = src_table->readSecretSharedPageFromDisk(src_pid);
            dst_table->flushPage(dst_pid, src_page.data());

        }
    }

}


void BufferPoolManager::flushPage(const PageId &pid) {
    if(position_map_.find(pid) != position_map_.end() && position_map_.at(pid).dirty_) {
        int slot = position_map_.at(pid).slot_id_;

        emp::Bit *src =  buffer_pool_.data() + slot * page_size_bits_;
        // cout << "Flushing page " << pid.toString() << " from slot " << slot <<  " reading from  offset " <<   (src - buffer_pool_.data()) << " bits." <<  endl;

        auto tbl = table_catalog_.at(pid.table_id_);
        assert(tbl != nullptr);

        tbl->flushPage(pid, src);
        position_map_.at(pid).dirty_ = false;
    }
}


void BufferPoolManager::getPage(const PageId &pid, const int & slot ) {
    assert(table_catalog_.find(pid.table_id_) != table_catalog_.end());

    emp::Bit *dst =  buffer_pool_.data() + slot * page_size_bits_;
    // cout << "BPM retrieving page " << pid.toString() << " into slot " << slot <<  " reading from  offset " <<   (dst - buffer_pool_.data()) << " bits." <<  endl;
    auto tbl = table_catalog_.at(pid.table_id_);
    assert(tbl != nullptr);
    tbl->getPage(pid, dst);
    position_map_[pid] = PositionMapEntry(slot, false, false);
    reverse_position_map_[slot] = pid;
}

#endif