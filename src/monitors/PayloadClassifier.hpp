#pragma once

// ---------------------------------------------------------------------------
// sentinel::monitors::PayloadClassifier
// Pure C++20 regex & Shannon entropy classifier for sensitive clipboard text.
// ZERO <windows.h> dependency for clean unit testing and portability.
// ---------------------------------------------------------------------------

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace sentinel::monitors {

// ---------------------------------------------------------------------------
// SecretType – categories of sensitive data
// ---------------------------------------------------------------------------
enum class SecretType : uint8_t {
    None,
    OpenAiKey,
    AwsAccessKey,
    GitHubToken,
    PrivateKey,
    JwtToken,
    HexSecret,
    HighEntropyToken
};

// ---------------------------------------------------------------------------
// ClassificationResult – structured outcome without storing raw secrets
// ---------------------------------------------------------------------------
struct ClassificationResult {
    bool        isSensitive{ false };
    SecretType  type{ SecretType::None };
    std::string category;      // e.g. "OpenAI API Key", "AWS Access Key"
    std::string maskedPreview; // e.g. "sk-proj-...89A"
    std::string reason;        // e.g. "Matched pattern with entropy 4.62"
    double      entropy{ 0.0 };
};

// ---------------------------------------------------------------------------
// Functions
// ---------------------------------------------------------------------------

// Calculates the Shannon entropy (in bits per symbol) of the input text.
[[nodiscard]] double calculateShannonEntropy(std::string_view text);

// Returns a masked preview string (e.g., "0x71C...89A" or "sk-p...90Z").
// Never exposes the internal raw payload.
[[nodiscard]] std::string maskSensitive(std::string_view text,
                                        std::size_t      prefixLen = 4,
                                        std::size_t      suffixLen = 4);

// Inspects text for sensitive patterns and high entropy tokens.
[[nodiscard]] ClassificationResult classifyPayload(std::string_view text);

} // namespace sentinel::monitors
