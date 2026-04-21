#ifndef _CRYPTO_MANAGER_H
#define _CRYPTO_MANAGER_H

#include <common/defs.h>

namespace vaultdb {

    template <typename B> class QueryTable;

    // Legacy CryptoManager interface (MPC-focused)
    // Kept for backward compatibility with existing operators
    // New code should use EmpManager or FheManager directly via SystemConfiguration
    class CryptoManager {
    public:
        virtual size_t getCommCost() const = 0;
        virtual size_t andGateCount() const = 0;
        virtual size_t getTableCardinality(const int & local_cardinality) = 0;
        virtual void feed(Bit *labels, int party, const bool *b, int bit_cnt) = 0;
        virtual void reveal(bool *dst, const int & party, Bit *src, const int & bit_cnt) = 0;
        virtual string revealToString(const emp::Integer & i, const int & party = PUBLIC) const = 0;
        virtual void flush() = 0;
        virtual QueryTable<Bit> *secretShare(const QueryTable<bool> *src) = 0;
        virtual int sendingParty() const = 0;
        virtual void sendPublic(const int & to_send) = 0;
        virtual int recvPublic() = 0;
        virtual void setDelta(const block & delta) = 0;

        virtual ~CryptoManager() = default;

        static string cryptoModeString(const CryptoMode & mode) {
            switch (mode) {
                case CryptoMode::PLAIN:
                    return "plain";
                case CryptoMode::EMP_SH2PC:
                    return "emp::sh2pc";
                case CryptoMode::EMP_SH2PC_OUTSOURCED:
                    return "emp::sh2pc_outsourced";
                case CryptoMode::EMP_ZK_MODE:
                    return "emp::zk";
                case CryptoMode::EMP_OUTSOURCED:
                    return "emp::outsourced";
                case CryptoMode::OPENFHE:
                    return "openFHE";
                default:
                    return "";
            }
        }
    };

}
#endif
