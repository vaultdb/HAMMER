#ifndef FHE_QUANTIZATION_H_
#define FHE_QUANTIZATION_H_

#include <vector>
#include <complex>
#include <cstdint>

namespace vaultdb {

    // Whether to treat integers as signed during bit extraction
    constexpr bool USE_SIGNED_ENCODING = true;

    double computeBias(int precision);

    // Extracts `length` bits from `num` starting at `start` bit.
    int extractBits(double num, int start, int length);

    // Splits a number into `w` parts each of `Bg` bits.
    std::vector<double> splitNumber(double x, int w, int Bg, double bias);

    // Splits a vector of numbers into quantized parts for homomorphic encryption.
    std::vector<std::vector<double>> quantization(const std::vector<double>& vec,
                                                  uint32_t precision,
                                                  uint32_t Bg);

    // Merges quantized parts back into the original number (for debug or validation).
    std::vector<double> merge_quant(const std::vector<std::vector<double>>& vec,
                                    uint32_t precision,
                                    uint32_t Bg);

    std::vector<double> splitNumberFixedPoint(double x, int w, int Bg, double scaleFactor);
    int64_t combineNumberFixedPoint(const std::vector<double>& parts, int w, int Bg);
    std::vector<std::vector<double>> quantizationFixedPoint(const std::vector<double>& vec, uint32_t precision, uint32_t Bg, double scaleFactor);
    std::vector<double> merge_quantFixedPoint(std::vector<std::vector<double>> vec, uint32_t precision, uint32_t Bg, double scaleFactor);

    // Combines `w` parts into a single integer by left-shifting.
    int combineNumber(const std::vector<double>& parts, int w, int Bg);

    // Splits a long vector into slot-sized vectors for batch encoding.
    std::vector<std::vector<double>> split_slots(const std::vector<double>& vec,
                                                 uint32_t num_slots);

    // Extracts real parts from CKKS output (for testing/decryption inspection).
    std::vector<double> extractRealParts(const std::vector<std::complex<double>>& enc);

} // namespace vaultdb

#endif // FHE_QUANTIZATION_H_