#ifndef PILOGTOOLS_LOGPARSER_H
#define PILOGTOOLS_LOGPARSER_H

#include <string>
#include <vector>
#include <regex>

// One Primary-period: start/end as display strings "YYYY-MM-DD HH:MM:SS".
struct PrimaryPeriod {
    std::string start;
    std::string end;
    bool        openEnded;   // true => interface still Primary at end of log
};

struct DateTimeParts {
    int y, mo, d, h, mi, s;
};

// Port of pi_log_tools.py (LogParser + separate_interface_instances).
class LogParser {
public:
    LogParser(const std::string& pointSource, const std::string& interfaceId);

    // Feature 1: findPrimaryPeriods + buildPrimaryResults
    void        findPrimaryPeriods(const std::string& fullText);
    std::string buildPrimaryResults() const;

    // Feature 2: separateInterfaces
    // Returns pairs of {tabName, content}.
    static std::vector<std::pair<std::string, std::string>>
    separateInterfaces(const std::string& fullText);

private:
    void processPrimaryEntry(const std::string& fullMessage);

    std::string pointSource_;
    std::string interfaceId_;

    std::vector<PrimaryPeriod> periods_;
    std::string                firstMatchState_;
    bool                       hasFirstMatch_ = false;
    bool                       inPrimary_     = false;
    std::string                primaryStartRaw_;
    DateTimeParts              primaryStartParts_{};

    std::regex pattern_;
};

// Shared helpers
std::vector<std::string> splitLinesKeepNewline(const std::string& s);
bool  parseTimestamp(const std::string& s, DateTimeParts& out);
std::string formatDateTime(const DateTimeParts& p);
long long toSortKey(const DateTimeParts& p);
bool  endsWith(const std::string& s, const std::string& suf);
std::string trim(const std::string& s);
std::string escapeRegex(const std::string& s);

// Feature 3: join every message onto a single line. A message starts at a
// header line ("X dd-Mon-yy HH:MM:SS ...") and runs up to (but not
// including) the next header line; all of its continuation lines/paragraphs
// (blank-line separated or not, ">>"-prefixed or not) are collapsed onto the
// header's line, separated by single spaces.
std::string joinMessagesOntoOneLine(const std::string& fullText);

#endif
