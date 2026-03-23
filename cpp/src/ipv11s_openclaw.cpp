#include <algorithm>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace ipv11s {

enum class Mode { P2P, Centralized, Hybrid };

struct SPD {
  std::string role;
  std::string affiliation;
  std::unordered_set<std::string> scope;
  double trustInstitutional;
  double trustPeer;
  double taskReliability;
  double policyViolations;
  std::string cultureProfileId;
  std::time_t validUntilEpoch;
  int evidenceCount;
};

struct Agent {
  std::string id;
  std::vector<std::string> services;
  std::string endpoint;
  std::string domain;
  SPD spd;
  std::unordered_map<std::string, double> endorsements;
  bool revoked = false;
};

struct Decision {
  bool allow;
  bool stageAReachable;
  bool stageBLegitimate;
  std::string reason;
  double trustScoreSrc;
  double trustScoreDst;
  std::string policyAssertionSummary;
  std::string trustRangeExtension;
};

class OpenClawController {
 public:
  void RegisterAgent(const Agent& agent) { agents_[agent.id] = agent; }

  bool Endorse(const std::string& fromAgent, const std::string& toAgent,
               double score) {
    auto src = agents_.find(fromAgent);
    auto dst = agents_.find(toAgent);
    if (src == agents_.end() || dst == agents_.end()) {
      return false;
    }
    dst->second.endorsements[fromAgent] = std::clamp(score, 0.0, 1.0);
    return true;
  }

  void Bootstrap() {
    agents_.clear();
    const auto now = std::time(nullptr);
    const auto thirtyDays = 30 * 24 * 60 * 60;
    const auto validUntil = now + thirtyDays;

    RegisterAgent(Agent{
        .id = "agent-alpha",
        .services = {"triage", "routing-assist"},
        .endpoint = "ipv11://society/a/alpha",
        .domain = "hospital-net",
        .spd = SPD{
            .role = "triage-coordinator",
            .affiliation = "hospital-a",
            .scope = {"read-case", "approve-transfer",
                      "critical-transfer-execute"},
            .trustInstitutional = 0.98,
            .trustPeer = 0.90,
            .taskReliability = 0.96,
            .policyViolations = 0.01,
            .cultureProfileId = "clinical-v1",
            .validUntilEpoch = validUntil,
            .evidenceCount = 120,
        },
    });

    RegisterAgent(Agent{
        .id = "agent-beta",
        .services = {"bed-allocation", "intake"},
        .endpoint = "ipv11://society/b/beta",
        .domain = "hospital-net",
        .spd = SPD{
            .role = "allocation-manager",
            .affiliation = "hospital-b",
            .scope = {"read-case", "approve-transfer",
                      "critical-transfer-execute"},
            .trustInstitutional = 0.95,
            .trustPeer = 0.88,
            .taskReliability = 0.94,
            .policyViolations = 0.01,
            .cultureProfileId = "clinical-v1",
            .validUntilEpoch = validUntil,
            .evidenceCount = 88,
        },
    });

    Endorse("agent-alpha", "agent-beta", 0.92);
    Endorse("agent-beta", "agent-alpha", 0.90);
  }

  Decision Evaluate(const std::string& srcId, const std::string& dstId,
                    const std::string& action, Mode mode,
                    const std::string& authToken) const {
    const auto srcIt = agents_.find(srcId);
    const auto dstIt = agents_.find(dstId);

    if (srcIt == agents_.end() || dstIt == agents_.end()) {
      return Deny("agent not found", false, false, 0.0, 0.0,
                  "LOOKUP_FAIL", "VERY_LOW");
    }

    const auto& src = srcIt->second;
    const auto& dst = dstIt->second;

    if (IsInvalid(src) || IsInvalid(dst)) {
      return Deny("agent revoked or SPD expired", true, false, TrustScore(src),
                  TrustScore(dst), "SPD_INVALID", "VERY_LOW");
    }

    const bool stageA = !src.endpoint.empty() && !dst.endpoint.empty();
    if (!stageA) {
      return Deny("Stage A failed: endpoint not reachable", false, false, 0.0,
                  0.0, "REACHABILITY_FAIL", "VERY_LOW");
    }

    if (mode == Mode::Centralized || mode == Mode::Hybrid) {
      const auto expected = "DA-SIGNED::" + src.domain + "::" + src.id;
      if (authToken != expected) {
        const auto s = TrustScore(src);
        const auto d = TrustScore(dst);
        return Deny(
            "Centralized auth failed (invalid domain authority token)", true,
            false, s, d, "AUTH_FAIL", TrustBand(std::min(s, d)));
      }
    }

    const auto srcScore = TrustScore(src);
    const auto dstScore = TrustScore(dst);
    const auto threshold = PolicyThreshold(action);
    const bool highRisk = threshold >= 0.80;
    const bool cultureOk =
        (src.spd.cultureProfileId == dst.spd.cultureProfileId) || !highRisk;
    const bool scopeOk = src.spd.scope.find(action) != src.spd.scope.end();
    const bool trustOk = srcScore >= threshold && dstScore >= threshold;
    const bool stageB = cultureOk && scopeOk && trustOk;

    std::ostringstream reason;
    if (stageB) {
      reason << "allow";
    } else {
      bool first = true;
      if (!scopeOk) {
        reason << "source action out of scoped role";
        first = false;
      }
      if (!trustOk) {
        if (!first) reason << "; ";
        reason << "trust below threshold " << std::fixed << std::setprecision(2)
               << threshold;
        first = false;
      }
      if (!cultureOk) {
        if (!first) reason << "; ";
        reason << "culture profile mismatch for high-risk action";
      }
    }

    std::ostringstream summary;
    summary << "MODE=" << ModeName(mode) << "|THRESHOLD=" << std::fixed
            << std::setprecision(2) << threshold;

    return Decision{
        .allow = stageB,
        .stageAReachable = true,
        .stageBLegitimate = stageB,
        .reason = reason.str(),
        .trustScoreSrc = srcScore,
        .trustScoreDst = dstScore,
        .policyAssertionSummary = summary.str(),
        .trustRangeExtension = TrustBand(std::min(srcScore, dstScore)),
    };
  }

 private:
  std::unordered_map<std::string, Agent> agents_;

  static constexpr double kAlpha = 0.40;
  static constexpr double kBeta = 0.25;
  static constexpr double kGamma = 0.25;
  static constexpr double kDelta = 0.10;

  static bool IsInvalid(const Agent& agent) {
    const auto now = std::time(nullptr);
    return agent.revoked || agent.spd.validUntilEpoch <= now;
  }

  static double TrustScore(const Agent& agent) {
    double peerComponent = agent.spd.trustPeer;
    if (!agent.endorsements.empty()) {
      double total = 0.0;
      for (const auto& [_, score] : agent.endorsements) {
        total += score;
      }
      peerComponent = total / static_cast<double>(agent.endorsements.size());
    }

    const double score = kAlpha * agent.spd.trustInstitutional +
                         kBeta * peerComponent +
                         kGamma * agent.spd.taskReliability -
                         kDelta * agent.spd.policyViolations;
    return std::clamp(score, 0.0, 1.0);
  }

  static std::string TrustBand(double score) {
    if (score >= 0.80) return "HIGH";
    if (score >= 0.60) return "MEDIUM";
    if (score >= 0.35) return "LOW";
    return "VERY_LOW";
  }

  static double PolicyThreshold(const std::string& action) {
    const auto lower = ToLower(action);
    if (lower.find("critical") != std::string::npos ||
        lower.find("execute") != std::string::npos) {
      return 0.80;
    }
    if (lower.find("write") != std::string::npos ||
        lower.find("approve") != std::string::npos) {
      return 0.65;
    }
    return 0.45;
  }

  static std::string ToLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
  }

  static std::string ModeName(Mode mode) {
    switch (mode) {
      case Mode::P2P:
        return "p2p";
      case Mode::Centralized:
        return "centralized";
      case Mode::Hybrid:
        return "hybrid";
    }
    return "unknown";
  }

  static Decision Deny(const std::string& reason, bool stageA, bool stageB,
                       double srcScore, double dstScore,
                       const std::string& policySummary,
                       const std::string& trustRange) {
    return Decision{
        .allow = false,
        .stageAReachable = stageA,
        .stageBLegitimate = stageB,
        .reason = reason,
        .trustScoreSrc = srcScore,
        .trustScoreDst = dstScore,
        .policyAssertionSummary = policySummary,
        .trustRangeExtension = trustRange,
    };
  }
};

void PrintDecision(const std::string& label, const Decision& d) {
  std::cout << "=== " << label << " ===\n";
  std::cout << "{\n";
  std::cout << "  \"allow\": " << (d.allow ? "true" : "false") << ",\n";
  std::cout << "  \"stage_a_reachable\": " << (d.stageAReachable ? "true" : "false")
            << ",\n";
  std::cout << "  \"stage_b_legitimate\": " << (d.stageBLegitimate ? "true" : "false")
            << ",\n";
  std::cout << "  \"reason\": \"" << d.reason << "\",\n";
  std::cout << "  \"trust_score_src\": " << std::fixed << std::setprecision(3)
            << d.trustScoreSrc << ",\n";
  std::cout << "  \"trust_score_dst\": " << d.trustScoreDst << ",\n";
  std::cout << "  \"policy_assertion_summary\": \"" << d.policyAssertionSummary
            << "\",\n";
  std::cout << "  \"trust_range_extension\": \"" << d.trustRangeExtension << "\"\n";
  std::cout << "}\n\n";
}

}  // namespace ipv11s

int main() {
  using namespace ipv11s;

  OpenClawController controller;
  controller.Bootstrap();

  const auto allow = controller.Evaluate("agent-alpha", "agent-beta",
                                         "critical-transfer-execute",
                                         Mode::Hybrid,
                                         "DA-SIGNED::hospital-net::agent-alpha");
  PrintDecision("HYBRID AUTH (EXPECTED ALLOW)", allow);

  const auto denyAuth = controller.Evaluate("agent-alpha", "agent-beta",
                                            "critical-transfer-execute",
                                            Mode::Hybrid, "INVALID");
  PrintDecision("HYBRID AUTH (EXPECTED DENY)", denyAuth);

  const auto p2p = controller.Evaluate("agent-alpha", "agent-beta", "read-case",
                                       Mode::P2P, "");
  PrintDecision("P2P READ (EXPECTED ALLOW)", p2p);

  return 0;
}
