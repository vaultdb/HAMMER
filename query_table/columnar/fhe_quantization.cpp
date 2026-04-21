#include "query_table/columnar/fhe_quantization.h"
#include <cmath>

namespace vaultdb {
    double computeBias(int precision) {
        return USE_SIGNED_ENCODING ? std::pow(2.0, precision - 1) : 0.0;
    }

    std::vector<double> splitNumber(double x, int w, int Bg, double bias) {
        int64_t val = static_cast<int64_t>(std::round(x + bias));
        std::vector<double> result(w);
        for (int i = 0; i < w; ++i) {
            int start_bit = i * Bg;
            int64_t extracted = (val >> start_bit) & ((1LL << Bg) - 1);
            result[i] = static_cast<double>(extracted);
        }
        return result;
    }

    std::vector<std::vector<double>> quantization(const std::vector<double>& vec,
                                                  uint32_t precision, uint32_t Bg) {
        int w = precision / Bg;
        double bias = computeBias(precision);
        int length = vec.size();
        std::vector<std::vector<double>> quant_plain(w, std::vector<double>(length));

        for (int i = 0; i < length; ++i) {
            auto split_vi = splitNumber(vec[i], w, Bg, bias);
            for (int j = 0; j < w; ++j) {
                quant_plain[j][i] = split_vi[j];
            }
        }
        return quant_plain;
    }

    double combineNumber(const std::vector<double>& parts, int w, int Bg, double bias) {
        int64_t result = 0;
        for (int i = 0; i < w; ++i) {
            int64_t val = static_cast<int64_t>(std::round(parts[i]));
            result |= (val << (i * Bg));
        }
        return static_cast<double>(result - bias);
    }

    std::vector<double> merge_quant(const std::vector<std::vector<double>>& vec,
                                    uint32_t precision, uint32_t Bg) {
        int w = precision / Bg;
        double bias = computeBias(precision);
        int length = vec[0].size();
        std::vector<double> merged_plain(length);

        for (int i = 0; i < length; ++i) {
            std::vector<double> temp_v(w);
            for (int j = 0; j < w; ++j) {
                temp_v[j] = vec[j][i];
            }
            merged_plain[i] = combineNumber(temp_v, w, Bg, bias);
        }
        return merged_plain;
    }

    std::vector<double> splitNumberFixedPoint(double x, int w, int Bg, double scaleFactor) {
        int64_t scaled = static_cast<int64_t>(x * scaleFactor);
        std::vector<double> result;
        for (int i = 0; i < w; ++i) {
            int start_bit = i * Bg;
            int extracted = (scaled >> start_bit) & ((1 << Bg) - 1);
            result.push_back(static_cast<double>(extracted));
        }
        return result;
    }

    int64_t combineNumberFixedPoint(const std::vector<double>& parts, int w, int Bg) {
        int64_t result = 0;
        for (int i = 0; i < w; ++i) {
            int shift = (w - 1 - i) * Bg;
            result |= (static_cast<int64_t>(parts[i]) << shift);
        }
        return result;
    }

    std::vector<std::vector<double>> quantizationFixedPoint(const std::vector<double>& vec, uint32_t precision, uint32_t Bg, double scaleFactor) {
        int w = precision / Bg;
        int length = vec.size();
        std::vector<std::vector<double>> quant_plain(w, std::vector<double>(length));
        for (int i = 0; i < length; ++i) {
            auto split_vi = splitNumberFixedPoint(vec[i], w, Bg, scaleFactor);
            for (int j = 0; j < w; ++j) {
                quant_plain[j][i] = split_vi[j];
            }
        }
        return quant_plain;
    }

    std::vector<double> merge_quantFixedPoint(std::vector<std::vector<double>> vec, uint32_t precision, uint32_t Bg, double scaleFactor) {
        int w = precision / Bg;
        int length = vec[0].size();
        std::vector<double> merged_plain(length);
        for (int i = 0; i < length; ++i) {
            std::vector<double> parts(w);
            for (int j = 0; j < w; ++j) {
                parts[j] = vec[j][i];
            }
            int64_t combined = combineNumberFixedPoint(parts, w, Bg);
            merged_plain[i] = static_cast<double>(combined) / scaleFactor;
        }
        return merged_plain;
    }

    std::vector<std::vector<double>> split_slots(const std::vector<double>& vec,
                                                 uint32_t num_slots) {
        int length = vec.size();
        int ct_block_size = length / num_slots;
        std::vector<std::vector<double>> splited_plain(ct_block_size,
                                                       std::vector<double>(num_slots));

        for (int i = 0; i < ct_block_size; ++i) {
            splited_plain[i].assign(vec.begin() + i * num_slots,
                                    vec.begin() + (i + 1) * num_slots);
        }
        return splited_plain;
    }

    std::vector<double> extractRealParts(const std::vector<std::complex<double>>& enc) {
        std::vector<double> realParts;
        realParts.reserve(enc.size());
        for (const auto& elem : enc) {
            realParts.push_back(elem.real());
        }
        return realParts;
    }

} // namespace vaultdb
