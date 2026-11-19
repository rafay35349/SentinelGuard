// SentinelGuard – tests/VerifyMilestone3.cpp
// Automated verification suite for Milestone 3 (PayloadClassifier & masking).
// Pure C++20 with zero <windows.h> dependency.

#include <iostream>
#include <string>
#include <string_view>
#include <cmath>

#include "monitors/PayloadClassifier.hpp"

namespace {

int g_failures = 0;

void reportTest(bool passed, const std::string& name, const std::string& detail = "")
{
    if (passed) {
        std::cout << "  [PASS] " << name;
        if (!detail.empty()) std::cout << " (" << detail << ")";
        std::cout << "\n";
    } else {
        std::cout << "  [FAIL] " << name;
        if (!detail.empty()) std::cout << " -> " << detail;
        std::cout << "\n";
        ++g_failures;
    }
}

} // anonymous namespace

int main()
{
    std::cout << "========================================================\n";
    std::cout << "  SentinelGuard – Milestone 3 Automated Verification\n";
    std::cout << "========================================================\n\n";

    // -------------------------------------------------------------------------
    // TEST SUITE 1: Shannon Entropy Calculations
    // -------------------------------------------------------------------------
    std::cout << "[Suite 1] Shannon Entropy Calculations\n";

    // Uniform single-character string: entropy must be 0.0
    const double zeroEntropy = sentinel::monitors::calculateShannonEntropy("AAAAAAAAAA");
    reportTest(std::abs(zeroEntropy - 0.0) < 0.001, "Monotonic string has 0 entropy",
               std::to_string(zeroEntropy));

    // Two equally distributed characters: entropy must be 1.0 bit
    const double oneEntropy = sentinel::monitors::calculateShannonEntropy("ABABABABABAB");
    reportTest(std::abs(oneEntropy - 1.0) < 0.001, "Equally balanced 2-char string has 1.0 entropy",
               std::to_string(oneEntropy));

    // High entropy random string (base64 random token): entropy > 4.5
    const std::string highEntropySample = "k9J2mZ8xQv4pL1wY7rT3sB6nD0eF5gH8";
    const double highEntropy = sentinel::monitors::calculateShannonEntropy(highEntropySample);
    reportTest(highEntropy > 4.5, "Random 32-char token has high entropy (> 4.5)",
               std::to_string(highEntropy));

    // -------------------------------------------------------------------------
    // TEST SUITE 2: Pattern Recognition & Secret Classification
    // -------------------------------------------------------------------------
    std::cout << "\n[Suite 2] Pattern Recognition & Secret Classification\n";

    // 2.1: OpenAI API Key
    {
        const std::string sample = "sk-proj-abc1234567890def1234567890xyz";
        const auto res = sentinel::monitors::classifyPayload(sample);
        reportTest(res.isSensitive && res.type == sentinel::monitors::SecretType::OpenAiKey,
                   "OpenAI API key detected", res.category);
        reportTest(res.maskedPreview.find("...") != std::string::npos &&
                   res.maskedPreview != sample,
                   "OpenAI key masked properly", res.maskedPreview);
    }

    // 2.2: AWS Access Key
    {
        const std::string sample = "AKIAIOSFODNN7EXAMPLE";
        const auto res = sentinel::monitors::classifyPayload(sample);
        reportTest(res.isSensitive && res.type == sentinel::monitors::SecretType::AwsAccessKey,
                   "AWS Access Key detected", res.category);
        reportTest(res.maskedPreview == "AKIA...MPLE",
                   "AWS key masked properly", res.maskedPreview);
    }

    // 2.3: GitHub Personal Access Token
    {
        const std::string sample = "ghp_1234567890abcdef1234567890abcdef1234";
        const auto res = sentinel::monitors::classifyPayload(sample);
        reportTest(res.isSensitive && res.type == sentinel::monitors::SecretType::GitHubToken,
                   "GitHub token detected", res.category);
        reportTest(res.maskedPreview.find("...") != std::string::npos,
                   "GitHub token masked properly", res.maskedPreview);
    }

    // 2.4: RSA Private Key Header
    {
        const std::string sample = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...";
        const auto res = sentinel::monitors::classifyPayload(sample);
        reportTest(res.isSensitive && res.type == sentinel::monitors::SecretType::PrivateKey,
                   "Private Key detected", res.category);
        reportTest(res.maskedPreview == "-----BEGIN [REDACTED] PRIVATE KEY-----",
                   "Private Key masked properly", res.maskedPreview);
    }

    // 2.5: JSON Web Token (JWT)
    {
        const std::string sample = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozG6pGgsmek7xCPmzkbEbXWstb9sQ";
        const auto res = sentinel::monitors::classifyPayload(sample);
        reportTest(res.isSensitive && res.type == sentinel::monitors::SecretType::JwtToken,
                   "JWT token detected", res.category);
        reportTest(res.maskedPreview.find("...") != std::string::npos,
                   "JWT token masked properly", res.maskedPreview);
    }

    // 2.6: Cryptographic Hex Secret
    {
        const std::string sample = "0x71C829482739482739482739482739482739489A";
        const auto res = sentinel::monitors::classifyPayload(sample);
        reportTest(res.isSensitive && res.type == sentinel::monitors::SecretType::HexSecret,
                   "Hex Secret detected", res.category);
        reportTest(res.maskedPreview.find("0x71C...") != std::string::npos,
                   "Hex secret masked properly", res.maskedPreview);
    }

    // 2.7: Non-sensitive prose / code (Negative test)
    {
        const std::string sample = "Hello World! This is standard normal clipboard text for copy pasting.";
        const auto res = sentinel::monitors::classifyPayload(sample);
        reportTest(!res.isSensitive, "Standard English text is not flagged as sensitive");
    }

    // -------------------------------------------------------------------------
    // Final Summary
    // -------------------------------------------------------------------------
    std::cout << "\n========================================================\n";
    if (g_failures == 0) {
        std::cout << "  ALL MILESTONE 3 TESTS PASSED (0 failures)\n";
    } else {
        std::cout << "  VERIFICATION FAILED: " << g_failures << " test(s) failed\n";
    }
    std::cout << "========================================================\n";

    return (g_failures == 0) ? 0 : 1;
}
