#include "LogParser.h"

#include <algorithm>
#include <cstdio>
#include <map>
#include <climits>

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

std::vector<std::string> splitLinesKeepNewline(const std::string& s)
{
    std::vector<std::string> out;
    size_t start = 0;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\n') {
            out.push_back(s.substr(start, i - start + 1)); // keep the '\n'
            start = i + 1;
        }
    }
    if (start < s.size())
        out.push_back(s.substr(start));
    return out;
}

static int digitsAt(const std::string& s, size_t at, size_t n)
{
    int v = 0;
    for (size_t k = 0; k < n; ++k) {
        char c = s[at + k];
        if (c < '0' || c > '9')
            return -1;
        v = v * 10 + (c - '0');
    }
    return v;
}

bool parseTimestamp(const std::string& s, DateTimeParts& p)
{
    // expected "dd-Mon-yy HH:MM:SS" e.g. "04-Aug-24 13:45:22" (18 chars)
    if (s.size() < 18)
        return false;

    int d = digitsAt(s, 0, 2);
    if (d < 0 || s[2] != '-')
        return false;

    static const char* months[12] = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
    };
    std::string mon = s.substr(3, 3);
    int mo = -1;
    for (int i = 0; i < 12; ++i)
        if (mon == months[i]) { mo = i + 1; break; }
    if (mo < 0 || s[6] != '-')
        return false;

    int yy = digitsAt(s, 7, 2);
    if (yy < 0 || s[9] != ' ')
        return false;

    int h   = digitsAt(s, 10, 2);
    int mi  = digitsAt(s, 13, 2);
    int sec = digitsAt(s, 16, 2);
    if (h < 0 || mi < 0 || sec < 0)
        return false;

    // Match Python strptime %y behaviour: 00-68 -> 2000s, 69-99 -> 1900s.
    p.y  = yy >= 69 ? 1900 + yy : 2000 + yy;
    p.mo = mo;
    p.d  = d;
    p.h  = h;
    p.mi = mi;
    p.s  = sec;
    return true;
}

std::string formatDateTime(const DateTimeParts& p)
{
    char buf[32];
    std::snprintf(buf, sizeof buf, "%04d-%02d-%02d %02d:%02d:%02d",
                  p.y, p.mo, p.d, p.h, p.mi, p.s);
    return std::string(buf);
}

long long toSortKey(const DateTimeParts& p)
{
    return (long long)p.y * 10000000000LL
         + (long long)p.mo * 100000000LL
         + (long long)p.d * 1000000LL
         + (long long)p.h * 10000LL
         + (long long)p.mi * 100LL
         + (long long)p.s;
}

bool endsWith(const std::string& s, const std::string& suf)
{
    return s.size() >= suf.size() &&
           s.compare(s.size() - suf.size(), suf.size(), suf) == 0;
}

std::string trim(const std::string& s)
{
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos)
        return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

std::string escapeRegex(const std::string& s)
{
    std::string out;
    out.reserve(s.size() * 2);
    static const char special[] = ".^$|()[]{}*+?\\";
    for (char c : s) {
        for (char sc : special)
            if (c == sc) { out += '\\'; break; }
        out += c;
    }
    return out;
}

// --------------------------------------------------------------------------
// Feature 1: find time ranges when an interface was primary
// --------------------------------------------------------------------------

LogParser::LogParser(const std::string& pointSource, const std::string& interfaceId)
    : pointSource_(pointSource)
    , interfaceId_(interfaceId)
{
    std::string ps = escapeRegex(pointSource_);
    std::string id = escapeRegex(interfaceId_);

    // Port of the Python LogParser pattern (RE with re.DOTALL behaviour;
    // entries are joined with spaces so there are no newlines to cross).
    std::string pat =
        "[A-Z]\\s+"
        "(\\d{2}-\\w{3}-\\d{2} \\d{2}:\\d{2}:\\d{2})\\s+"
        "(?:[^:]+):(?:[^:]+):" + ps + "\\s+"
        "\\|\\s*" + id + "\\s*\\|\\s*\\d+\\s+"
        "\\(\\d+\\)\\s+"
        ">>\\s+UniInt failover: (?:"
          "Interface in the \"(Primary|Backup)\" state(?:\\. Communication with PI is in error\\.)?"
          "|Interface transitioning from (Primary|Backup) to (Primary|Backup),"
        ").*";

    pattern_ = std::regex(pat, std::regex::ECMAScript);
}

void LogParser::processPrimaryEntry(const std::string& fullMessage)
{
    std::cmatch m;
    if (!std::regex_search(fullMessage.c_str(), m, pattern_))
        return;

    // m[1] = timestamp, m[2] = state (in), m[3] = trans_from, m[4] = trans_to
    std::string state = m[2].matched ? std::string(m[2].first, m[2].second)
                                     : std::string(m[3].first, m[3].second);
    std::string ts = std::string(m[1].first, m[1].second);

    DateTimeParts parts{};
    if (!parseTimestamp(ts, parts))
        return;

    if (!hasFirstMatch_) {
        hasFirstMatch_ = true;
        firstMatchState_ = state;
        if (endsWith(fullMessage, "Communication with PI is in error."))
            firstMatchState_ = "Backup_with_error";
    }

    if (state == "Primary") {
        if (!inPrimary_) {
            inPrimary_ = true;
            primaryStartRaw_ = ts;
            primaryStartParts_ = parts;
        }
    } else if (state == "Backup") {
        if (inPrimary_) {
            PrimaryPeriod pp;
            pp.start     = formatDateTime(primaryStartParts_);
            pp.end       = formatDateTime(parts);
            pp.openEnded = false;
            periods_.push_back(pp);
            inPrimary_ = false;
        }
    }
}

void LogParser::findPrimaryPeriods(const std::string& fullText)
{
    periods_.clear();
    hasFirstMatch_ = false;
    inPrimary_     = false;

    static const std::regex logLineRe("^[A-Z] \\d{2}-\\w{3}-\\d{2} \\d{2}:\\d{2}:\\d{2}");

    std::vector<std::string> lines = splitLinesKeepNewline(fullText);
    std::vector<std::string> currentEntry;

    auto flush = [&]() {
        if (currentEntry.empty())
            return;
        std::string msg;
        for (size_t i = 0; i < currentEntry.size(); ++i) {
            std::string t = trim(currentEntry[i]);
            if (t.empty())
                continue;
            if (!msg.empty())
                msg += " ";
            msg += t;
        }
        if (!msg.empty())
            processPrimaryEntry(msg);
        currentEntry.clear();
    };

    for (const std::string& line : lines) {
        if (std::regex_search(line, logLineRe))
            flush();
        currentEntry.push_back(line);
    }
    flush();

    if (inPrimary_) {
        PrimaryPeriod pp;
        pp.start     = formatDateTime(primaryStartParts_);
        pp.end       = "";
        pp.openEnded = true;
        periods_.push_back(pp);
        inPrimary_ = false;
    }
}

std::string LogParser::buildPrimaryResults() const
{
    std::string out = "Primary State Time Ranges:\n";

    if (firstMatchState_ == "Primary" || firstMatchState_ == "Backup_with_error")
        out += "Interface was in Primary state at the beginning of the log.\n";
    else if (firstMatchState_ == "Backup")
        out += "Interface was in Backup state at the beginning of the log.\n";
    else
        out += "No matching failover state entries found in the log.\n";

    // Skip the first primary period if the interface was primary from the start.
    std::vector<PrimaryPeriod> periods = periods_;
    if (firstMatchState_ == "Primary" && !periods.empty())
        periods.erase(periods.begin());

    if (!periods.empty()) {
        for (const PrimaryPeriod& pp : periods) {
            if (pp.openEnded)
                out += "From " + pp.start + " to [still in Primary state at end of log]\n";
            else
                out += "From " + pp.start + " to " + pp.end + "\n";
        }
    } else if (periods_.empty()) {
        out += "No Primary state periods found.\n";
    }

    return out;
}

// --------------------------------------------------------------------------
// Feature 2: separate log messages for separate interface instances
// --------------------------------------------------------------------------

std::vector<std::pair<std::string, std::string>>
LogParser::separateInterfaces(const std::string& fullText)
{
    using Entry = std::pair<long long, std::string>; // {sortKey, message}

    std::map<std::string, std::vector<Entry>> buckets;
    std::vector<Entry>                        globalLogs;

    static const std::regex headerRe(
        "^[A-Z]\\s+\\d{2}-\\w{3}-\\d{2}\\s\\d{2}:\\d{2}:\\d{2}\\s+"
        "[^:]+:[^:]+:([^|]+)\\s+\\|\\s+(\\d+)\\s+\\|");
    static const std::regex logLineRe("^[A-Z] \\d{2}-\\w{3}-\\d{2} \\d{2}:\\d{2}:\\d{2}");
    static const std::regex tsRe("\\d{2}-\\w{3}-\\d{2} \\d{2}:\\d{2}:\\d{2}");

    std::vector<std::string> lines = splitLinesKeepNewline(fullText);
    std::string currentKey;              // "" => global
    std::vector<std::string> currentMessage;

    auto flush = [&]() {
        if (currentMessage.empty())
            return;
        std::string joined;
        for (const std::string& l : currentMessage)
            joined += l;

        long long skey = LLONG_MIN;
        std::smatch m;
        if (std::regex_search(joined, m, tsRe)) {
            DateTimeParts p;
            if (parseTimestamp(m.str(), p))
                skey = toSortKey(p);
        }

        if (currentKey.empty())
            globalLogs.push_back({skey, joined});
        else
            buckets[currentKey].push_back({skey, joined});

        currentMessage.clear();
    };

    for (const std::string& line : lines) {
        std::smatch hm;
        if (std::regex_search(line, hm, headerRe)) {
            flush();
            currentMessage.push_back(line);
            std::string ps = hm[1].str();
            std::string id = hm[2].str();
            currentKey = ps + "\x01" + id;
        } else if (std::regex_search(line, logLineRe)) {
            flush();
            currentMessage.push_back(line);
            currentKey = "";
        } else {
            currentMessage.push_back(line);
        }
    }
    flush();

    std::vector<std::pair<std::string, std::string>> results;
    for (const auto& kv : buckets) {
        size_t sep = kv.first.find('\x01');
        std::string name = kv.first.substr(0, sep) + "_" +
                           kv.first.substr(sep + 1) + ".txt";

        std::vector<Entry> combined = globalLogs;
        combined.insert(combined.end(), kv.second.begin(), kv.second.end());
        std::sort(combined.begin(), combined.end(),
                  [](const Entry& a, const Entry& b) {
                      if (a.first != b.first) return a.first < b.first;
                      return a.second < b.second;
                  });

        std::string content;
        for (const Entry& e : combined) {
            content += e.second;
            if (content.empty() || content.back() != '\n')
                content += '\n';
        }
        results.emplace_back(name, content);
    }

    std::sort(results.begin(), results.end(),
              [](const auto& a, const auto& b) { return a.first < b.first; });
    return results;
}

// --------------------------------------------------------------------------
// Feature 3: join every message onto one line
// --------------------------------------------------------------------------

std::string joinMessagesOntoOneLine(const std::string& fullText)
{
    static const std::regex logLineRe("^[A-Z] \\d{2}-\\w{3}-\\d{2} \\d{2}:\\d{2}:\\d{2}");

    std::vector<std::string> lines = splitLinesKeepNewline(fullText);
    std::vector<std::string> current;
    std::string out;

    auto flush = [&]() {
        if (current.empty())
            return;
        std::string msg;
        for (const std::string& l : current) {
            std::string t = trim(l);
            if (t.empty())
                continue;
            if (!msg.empty())
                msg += " ";
            msg += t;
        }
        if (!msg.empty()) {
            out += msg;
            out += "\n";
        }
        current.clear();
    };

    for (const std::string& line : lines) {
        if (std::regex_search(line, logLineRe))
            flush();
        current.push_back(line);
    }
    flush();

    return out;
}
