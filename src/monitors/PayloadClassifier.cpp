// SentinelGuard – src/monitors/PayloadClassifier.cpp
// Pure C++20 regex & Shannon entropy classifier for sensitive clipboard text.
// ZERO <windows.h> dependency.

#include "PayloadClassifier.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <regex>
#include <string>
#include <string_view>

namespace sentinel::monitors {

namespace {

// ── Named constants ──────────────────────────────────────────────────────────
constexpr std::size_t kMinHighEntropyLen     = 24;
constexpr std::size_t kMaxHighEntropyLen     = 256;
constexpr double      kEntropyThreshold      = 4.20;
constexpr std::size_t kDefaultPrefixLen      = 4;
constexpr std::size_t kDefaultSuffixLen      = 4;

// ── Pattern helpers ──────────────────────────────────────────────────────────
[[nodiscard]] bool startsWith(std::string_view str, std::string_view prefix)
{
    return str.size() >= prefix.size() &&
           str.compare(0, prefix.size(), prefix) == 0;
}

[[nodiscard]] bool hasWhitespace(std::string_view text)
{
    return std::any_of(text.begin(), text.end(), [](unsigned char c) {
        return std::isspace(c) != 0;
    });
}

[[nodiscard]] bool isAllHex(std::string_view text)
{
    return !text.empty() && std::all_of(text.begin(), text.end(), [](unsigned char c) {
        return std::isxdigit(c) != 0;
    });
}

[[nodiscard]] std::string formatEntropyStr(double ent)
{
    char buf[16]{};
    std::snprintf(buf, sizeof(buf), "%.2f", ent);
    return std::string(buf);
}

// ── Specific pattern checkers ────────────────────────────────────────────────
[[nodiscard]] bool isPrivateKey(std::string_view text)
{
    return text.find("-----BEGIN ") != std::string_view::npos &&
           text.find("PRIVATE KEY-----") != std::string_view::npos;
}

[[nodiscard]] bool isOpenAiKey(std::string_view text)
{
    if (startsWith(text, "sk-proj-") && text.size() >= 30) return true;
    if (startsWith(text, "sk-") && text.size() >= 24) return true;
    return false;
}

[[nodiscard]] bool isAwsKey(std::string_view text)
{
    if (text.size() != 20 || !startsWith(text, "AKIA")) return false;
    return std::all_of(text.begin() + 4, text.end(), [](unsigned char c) {
        return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z');
    });
}

[[nodiscard]] bool isGitHubToken(std::string_view text)
{
    constexpr std::array<std::string_view, 5> kPrefixes{{
        "ghp_", "gho_", "ghu_", "ghs_", "ghr_"
    }};
    for (const auto& p : kPrefixes) {
        if (startsWith(text, p) && text.size() >= 36) return true;
    }
    return false;
}

[[nodiscard]] bool isJwtToken(std::string_view text)
{
    if (!startsWith(text, "eyJ") || text.size() < 30) return false;
    const auto firstDot = text.find('.');
    if (firstDot == std::string_view::npos) return false;
    const auto secondDot = text.find('.', firstDot + 1);
    return secondDot != std::string_view::npos && secondDot > firstDot + 1;
}

[[nodiscard]] bool isHexSecret(std::string_view text)
{
    if (startsWith(text, "0x") && text.size() >= 34) {
        return isAllHex(text.substr(2));
    }
    if ((text.size() == 40 || text.size() == 64) && isAllHex(text)) {
        return true;
    }
    return false;
}

} // anonymous namespace

// ── calculateShannonEntropy ──────────────────────────────────────────────────
double calculateShannonEntropy(std::string_view text)
{
    if (text.empty()) return 0.0;

    std::array<std::size_t, 256> frequencies{};
    for (const unsigned char c : text) {
        ++frequencies[c];
    }

    const double totalLen = static_cast<double>(text.size());
    double entropy = 0.0;

    for (const std::size_t count : frequencies) {
        if (count > 0) {
            const double p = static_cast<double>(count) / totalLen;
            entropy -= p * std::log2(p);
        }
    }

    return entropy;
}

// ── maskSensitive ────────────────────────────────────────────────────────────
std::string maskSensitive(std::string_view text,
                          std::size_t      prefixLen,
                          std::size_t      suffixLen)
{
    if (text.empty()) return {};

    const std::size_t minLen = prefixLen + suffixLen + 2;
    if (text.size() < minLen) {
        if (text.size() <= 2) return "**";
        return std::string(text.substr(0, 1)) + "***" +
               std::string(text.substr(text.size() - 1));
    }

    return std::string(text.substr(0, prefixLen)) + "..." +
           std::string(text.substr(text.size() - suffixLen));
}

// ── classifyPayload ──────────────────────────────────────────────────────────
ClassificationResult classifyPayload(std::string_view text)
{
    ClassificationResult res{};
    if (text.empty()) return res;

    res.entropy = calculateShannonEntropy(text);

    if (isPrivateKey(text)) {
        res.isSensitive    = true;
        res.type           = SecretType::PrivateKey;
        res.category       = "Private Key";
        res.maskedPreview  = "-----BEGIN [REDACTED] PRIVATE KEY-----";
        res.reason         = "Matched cryptographic private key header";
        return res;
    }

    if (isOpenAiKey(text)) {
        res.isSensitive    = true;
        res.type           = SecretType::OpenAiKey;
        res.category       = "OpenAI API Key";
        res.maskedPreview  = maskSensitive(text, 7, kDefaultSuffixLen);
        res.reason         = "Matched OpenAI secret token format (entropy " +
                             formatEntropyStr(res.entropy) + ")";
        return res;
    }

    if (isAwsKey(text)) {
        res.isSensitive    = true;
        res.type           = SecretType::AwsAccessKey;
        res.category       = "AWS Access Key";
        res.maskedPreview  = maskSensitive(text, kDefaultPrefixLen, kDefaultSuffixLen);
        res.reason         = "Matched AWS 20-character Access Key ID";
        return res;
    }

    if (isGitHubToken(text)) {
        res.isSensitive    = true;
        res.type           = SecretType::GitHubToken;
        res.category       = "GitHub Personal Token";
        res.maskedPreview  = maskSensitive(text, kDefaultPrefixLen, kDefaultSuffixLen);
        res.reason         = "Matched GitHub PAT prefix format";
        return res;
    }

    if (isJwtToken(text)) {
        res.isSensitive    = true;
        res.type           = SecretType::JwtToken;
        res.category       = "JSON Web Token (JWT)";
        res.maskedPreview  = maskSensitive(text, 6, 6);
        res.reason         = "Matched compact serialization JWT structure";
        return res;
    }

    if (isHexSecret(text)) {
        res.isSensitive    = true;
        res.type           = SecretType::HexSecret;
        res.category       = "Cryptographic Hex Secret";
        res.maskedPreview  = maskSensitive(text, 5, kDefaultSuffixLen);
        res.reason         = "High-entropy hex credential (entropy " +
                             formatEntropyStr(res.entropy) + ")";
        return res;
    }

    if (text.size() >= kMinHighEntropyLen &&
        text.size() <= kMaxHighEntropyLen &&
        !hasWhitespace(text) &&
        res.entropy >= kEntropyThreshold)
    {
        res.isSensitive    = true;
        res.type           = SecretType::HighEntropyToken;
        res.category       = "High-Entropy Secret";
        res.maskedPreview  = maskSensitive(text, kDefaultPrefixLen, kDefaultSuffixLen);
        res.reason         = "High Shannon entropy token (entropy " +
                             formatEntropyStr(res.entropy) + ")";
        return res;
    }

    return res;
}

} // namespace sentinel::monitors
