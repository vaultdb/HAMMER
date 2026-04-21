#ifndef _EMP_MANAGER_
#define _EMP_MANAGER_
#include <common/defs.h>
#include <util/crypto_manager/crypto_manager.h>

// abstract class for managing interactions with EMP connection
// used to abstract away different branches, e.g., emp-rescu/emp-zk/emp-sh2pc
// can support multiple implementations in the same branch/repo

namespace vaultdb {

    // forward declaration
    template <typename B> class QueryTable;

    class EmpManager : public CryptoManager {
    public:
        virtual size_t getCommCost() const override = 0;
        virtual size_t andGateCount() const override = 0;
        virtual void feed(Bit *labels, int party, const bool *b, int bit_cnt) override= 0;
        virtual void flush() override = 0;
        virtual QueryTable<Bit> *secretShare(const QueryTable<bool> *src) override = 0;
        // sending party of 0 means 2PC, alice and bob both secret sharing
        // sending party of 10086 means TP is secret sharing
        virtual int sendingParty() const override = 0;
        // for use in OMPC, all others have no-op
        virtual void pack(Bit *src, Bit *dst, const int & bit_cnt) = 0;
        virtual void unpack(Bit *src, Bit *dst, const int & bit_cnt) = 0;

        // sendingParty sends an int to all parties
        virtual void sendPublic(const int & to_send) override = 0;
        // all others call recvPublic at the same time to get the int
        virtual int recvPublic() override = 0;

        virtual void setDelta(const block & delta) override = 0;
        virtual void reveal(bool *dst, const int & party, Bit *src, const int & bit_cnt) override = 0;
        virtual string revealToString(const emp::Integer & i, const int & party = PUBLIC) const override = 0;
        virtual size_t getTableCardinality(const int & local_cardinality) = 0;
        virtual ~EmpManager() {}

    };
}
#endif
