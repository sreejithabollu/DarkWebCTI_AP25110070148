import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.LocalDate;
import java.time.YearMonth;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Dark Web Cyber Threat Intelligence Analysis - end-to-end pipeline.
 * Usage: java Main.java [--data f] [--public f] [--gold f] [--out dir] [--k N] [--seed N]
 */
public final class Main {
    private static final StringBuilder REPORT = new StringBuilder();

    private static void out(String s) { REPORT.append(s).append('\n'); System.out.println(s); }
    private static String f(double d) { return String.format(Locale.ROOT, "%.3f", d); }
    private static String csv(String s) { return "\"" + s.replace("\"", "\"\"") + "\""; }

    private static String words(Vectorizer v, int[] ids) {
        StringBuilder sb = new StringBuilder();
        for (int id : ids) sb.append(sb.length() == 0 ? "" : ", ").append(v.vocab.get(id));
        return sb.toString();
    }

    public static void main(String[] args) throws Exception {
        Map<String, String> o = new HashMap<>();
        for (int i = 0; i + 1 < args.length; i += 2) o.put(args[i].replaceFirst("^--", ""), args[i + 1]);
        Path dataP = Path.of(o.getOrDefault("data", "data/sample_corpus.csv"));
        Path pubP = Path.of(o.getOrDefault("public", "data/public_reports.csv"));
        Path goldP = Path.of(o.getOrDefault("gold", "data/ioc_gold.csv"));
        Path outDir = Path.of(o.getOrDefault("out", "out"));
        long seed = Long.parseLong(o.getOrDefault("seed", "42"));

        SampleData.ensure(dataP, pubP, goldP);

        out("==============================================================");
        out(" DARK WEB CYBER THREAT INTELLIGENCE ANALYSIS (defensive CTI)");
        out("==============================================================");

        // ---------------------------------------------------------------- 1. Load, deduplicate, sort
        List<Doc> raw = DataLoader.loadCorpus(dataP);
        Set<String> seen = new HashSet<>();
        List<Doc> docs = new ArrayList<>();
        for (Doc d : raw) if (seen.add(d.text().toLowerCase(Locale.ROOT).replaceAll("\\s+", " ").trim())) docs.add(d);
        docs.sort(Comparator.comparing(Doc::date).thenComparing(Doc::id));
        int n = docs.size();

        String[] labels = new String[n];
        boolean labeled = true;
        for (int i = 0; i < n; i++) { labels[i] = docs.get(i).label(); if (labels[i].isBlank()) labeled = false; }
        List<String> classes = new ArrayList<>(new TreeSet<>(Arrays.asList(labels)));
        if (!labeled) classes.clear();

        out("\n[1] DATASET");
        out("File: " + dataP + "  (SHA-256 " + sha256(dataP).substring(0, 16) + "...)");
        out("Records loaded: " + raw.size() + ", duplicates removed before splitting: " + (raw.size() - n) + ", analysed: " + n);
        out("Date range: " + docs.get(0).date() + " .. " + docs.get(n - 1).date());
        Map<String, Integer> srcCount = new TreeMap<>();
        for (Doc d : docs) srcCount.merge(d.source(), 1, Integer::sum);
        out("Sources: " + srcCount);
        if (labeled) {
            Map<String, Integer> cb = new TreeMap<>();
            for (String l : labels) cb.merge(l, 1, Integer::sum);
            out("Class balance: " + cb);
        }

        // ---------------------------------------------------------------- 2. Privacy + preprocessing + IOC extraction
        List<Set<Ioc>> iocs = new ArrayList<>();
        List<List<String>> toks = new ArrayList<>();
        int piiCount = 0;
        for (Doc d : docs) {
            String rf = Preprocessor.refang(d.text());
            piiCount += Preprocessor.countPii(rf);
            String prepared = Preprocessor.redactPii(rf);
            iocs.add(IocExtractor.extract(prepared));
            toks.add(Preprocessor.tokenize(IocExtractor.strip(prepared)));
        }
        out("\n[2] PRIVACY: " + piiCount + " e-mail addresses / handles redacted before analysis.");

        out("\n[3] ENTITY (IOC) EXTRACTION");
        Map<String, Integer> typeCount = new TreeMap<>();
        for (Set<Ioc> s : iocs) for (Ioc x : s) typeCount.merge(x.type(), 1, Integer::sum);
        out("Extracted IOC counts by type: " + typeCount);
        if (Files.exists(goldP)) {
            Map<String, Set<Ioc>> gold = DataLoader.loadGold(goldP);
            Map<String, int[]> tally = new TreeMap<>();
            int[] all = new int[3];
            List<String> errors = new ArrayList<>();
            for (int i = 0; i < n; i++) {
                Set<Ioc> pred = iocs.get(i), g = gold.getOrDefault(docs.get(i).id(), Set.of());
                for (Ioc x : pred) {
                    int[] t = tally.computeIfAbsent(x.type(), k -> new int[3]);
                    if (g.contains(x)) { t[0]++; all[0]++; }
                    else { t[1]++; all[1]++; if (errors.size() < 8) errors.add("FALSE POSITIVE " + docs.get(i).id() + " " + x); }
                }
                for (Ioc x : g) if (!pred.contains(x)) {
                    int[] t = tally.computeIfAbsent(x.type(), k -> new int[3]);
                    t[2]++; all[2]++;
                    if (errors.size() < 8) errors.add("FALSE NEGATIVE " + docs.get(i).id() + " " + x);
                }
            }
            out("Evaluation against manual annotation (" + goldP + "):");
            for (var e : tally.entrySet()) {
                Metrics.PRF m = prf(e.getValue());
                out(String.format(Locale.ROOT, "  %-7s P=%s R=%s F1=%s  (tp=%d fp=%d fn=%d)", e.getKey(),
                        f(m.precision()), f(m.recall()), f(m.f1()), e.getValue()[0], e.getValue()[1], e.getValue()[2]));
            }
            Metrics.PRF mm = prf(all);
            out("  MICRO   P=" + f(mm.precision()) + " R=" + f(mm.recall()) + " F1=" + f(mm.f1()));
            out("Error analysis examples:");
            for (String e : errors) out("  " + e);
        } else out("(no gold file found - extraction evaluation skipped)");

        // ---------------------------------------------------------------- 4. Topic modelling baselines
        Vectorizer vec = new Vectorizer(toks, 2, 0.6);
        int K = Integer.parseInt(o.getOrDefault("k", String.valueOf(labeled ? classes.size() : 6)));
        out("\n[4] TOPIC MODELLING  (vocabulary=" + vec.size() + ", K=" + K + ", seed=" + seed + ")");

        KMeans km = KMeans.fit(vec.tfidf, K, seed, 10);
        List<int[]> kmTop = new ArrayList<>();
        for (int k = 0; k < K; k++) kmTop.add(km.topTerms(k, 10));
        evalClustering("TF-IDF + K-means", km.assign, kmTop, K, vec, labels, labeled);

        Lda lda = new Lda(vec.docs, vec.size(), K, 0.1, 0.01, 1000, seed);
        int[] ldaAssign = lda.dominantTopics();
        List<int[]> ldaTop = new ArrayList<>();
        for (int k = 0; k < K; k++) ldaTop.add(lda.topTerms(k, 10));
        evalClustering("LDA (collapsed Gibbs)", ldaAssign, ldaTop, K, vec, labels, labeled);
        out("Note: BERTopic / embedding clustering needs a pretrained transformer and is not part of the standard library;");
        out("      spherical K-means on TF-IDF vectors is the embedding-style clustering baseline implemented here.");

        // ---------------------------------------------------------------- 5. Supervised classification
        if (labeled) {
            out("\n[5] SUPERVISED CLASSIFICATION (Multinomial Naive Bayes vs majority baseline)");
            int cut = (int) Math.round(n * 0.7);
            int[] trT = new int[cut], teT = new int[n - cut];
            for (int i = 0; i < n; i++) { if (i < cut) trT[i] = i; else teT[i - cut] = i; }
            List<Integer> idx = new ArrayList<>();
            for (int i = 0; i < n; i++) idx.add(i);
            Collections.shuffle(idx, new Random(seed));
            int[] trR = new int[cut], teR = new int[n - cut];
            for (int i = 0; i < n; i++) { if (i < cut) trR[i] = idx.get(i); else teR[i - cut] = idx.get(i); }
            evalSplit("Random 70/30 split (in-distribution)", trR, teR, vec, labels, classes);
            evalSplit("Temporal split: train on earlier 70%, test on later 30% (shift)", trT, teT, vec, labels, classes);
        }

        // ---------------------------------------------------------------- 6. Temporal analysis
        out("\n[6] TEMPORAL ANALYSIS");
        TreeMap<YearMonth, List<Integer>> byMonth = new TreeMap<>();
        for (int i = 0; i < n; i++) byMonth.computeIfAbsent(YearMonth.from(docs.get(i).date()), k -> new ArrayList<>()).add(i);
        double[][] ldaShares = monthlyShares(ldaAssign, K, byMonth);
        double[][] kmShares = monthlyShares(km.assign, K, byMonth);
        out("Temporal stability = mean Jensen-Shannon divergence between consecutive months (lower = more stable)");
        out("  LDA     : " + f(meanJs(ldaShares)));
        out("  K-means : " + f(meanJs(kmShares)));
        StringBuilder monthly = new StringBuilder("month,n");
        for (int k = 0; k < K; k++) monthly.append(",topic").append(k);
        monthly.append('\n');
        int mi = 0;
        for (var e : byMonth.entrySet()) {
            monthly.append(e.getKey()).append(',').append(e.getValue().size());
            for (int k = 0; k < K; k++) monthly.append(',').append(f(ldaShares[mi][k]));
            monthly.append('\n');
            mi++;
        }
        out("LDA topic share in first vs last month:");
        for (int k = 0; k < K; k++)
            out(String.format(Locale.ROOT, "  topic %d: %s -> %s  [%s]", k, f(ldaShares[0][k]),
                    f(ldaShares[ldaShares.length - 1][k]), words(vec, Arrays.copyOf(ldaTop.get(k), 4))));

        int mid = n / 2;
        int[] dfEarly = new int[vec.size()], dfLate = new int[vec.size()];
        for (int i = 0; i < n; i++) for (int w : new HashSet<>(toIntList(vec.docs[i]))) { if (i < mid) dfEarly[w]++; else dfLate[w]++; }
        List<double[]> scores = new ArrayList<>();
        for (int w = 0; w < vec.size(); w++) {
            if (dfEarly[w] + dfLate[w] < 4) continue;
            double s = Math.log(((dfLate[w] + 0.5) / (n - mid + 1.0)) / ((dfEarly[w] + 0.5) / (mid + 1.0)));
            scores.add(new double[]{w, s});
        }
        scores.sort((a, b) -> Double.compare(b[1], a[1]));
        Set<String> publicTerms = loadPublicTerms(pubP);
        out("Emerging terms (late half vs early half of the period)   [* = absent from public advisories]:");
        for (int i = 0; i < Math.min(10, scores.size()); i++) {
            String w = vec.vocab.get((int) scores.get(i)[0]);
            out(String.format(Locale.ROOT, "  %-16s log-ratio=%s %s", w, f(scores.get(i)[1]), publicTerms.isEmpty() || publicTerms.contains(w) ? "" : "*"));
        }
        out("Fading terms:");
        for (int i = scores.size() - 1; i >= Math.max(0, scores.size() - 8); i--)
            out(String.format(Locale.ROOT, "  %-16s log-ratio=%s", vec.vocab.get((int) scores.get(i)[0]), f(scores.get(i)[1])));

        // ---------------------------------------------------------------- 7. Comparison with public security reporting
        out("\n[7] COMPARISON WITH PUBLIC SECURITY REPORTING");
        if (publicTerms.isEmpty()) out("(no public report corpus found at " + pubP + ")");
        else {
            out("Public advisory vocabulary: " + publicTerms.size() + " terms (document frequency >= 2)");
            double sum = 0;
            for (int k = 0; k < K; k++) {
                int hit = 0;
                for (int id : ldaTop.get(k)) if (publicTerms.contains(vec.vocab.get(id))) hit++;
                double cov = (double) hit / ldaTop.get(k).length;
                sum += 1 - cov;
                out(String.format(Locale.ROOT, "  LDA topic %d: coverage by public reporting=%s  novelty=%s  [%s]",
                        k, f(cov), f(1 - cov), words(vec, Arrays.copyOf(ldaTop.get(k), 5))));
            }
            out("Mean topic novelty vs public reporting: " + f(sum / K) + "  (higher = more signal beyond conventional reporting)");
        }

        // ---------------------------------------------------------------- 8. Reproducibility + artefacts
        out("\n[8] REPRODUCIBILITY");
        out("Java " + System.getProperty("java.version") + ", seed=" + seed + ", K=" + K + ", LDA alpha=0.1 beta=0.01 iters=1000, K-means restarts=10");
        out("Run date: " + LocalDate.now() + ", min_df=2, max_df=0.6, dedup before split, temporal split keeps later data unseen.");

        Files.createDirectories(outDir);
        StringBuilder ic = new StringBuilder("doc_id,date,type,value\n");
        for (int i = 0; i < n; i++)
            for (Ioc x : iocs.get(i))
                ic.append(docs.get(i).id()).append(',').append(docs.get(i).date()).append(',').append(x.type()).append(',').append(csv(x.value())).append('\n');
        Files.writeString(outDir.resolve("iocs.csv"), ic.toString(), StandardCharsets.UTF_8);
        Files.writeString(outDir.resolve("monthly_topic_share.csv"), monthly.toString(), StandardCharsets.UTF_8);
        Files.writeString(outDir.resolve("report.txt"), REPORT.toString(), StandardCharsets.UTF_8);
        System.out.println("\nArtefacts written to " + outDir.toAbsolutePath());
    }

    // -------------------------------------------------------------------- helpers
    private static Metrics.PRF prf(int[] t) { return Metrics.PRF.of(t[0], t[1], t[2]); }

    private static List<Integer> toIntList(int[] a) { List<Integer> l = new ArrayList<>(); for (int x : a) l.add(x); return l; }

    private static void evalClustering(String name, int[] assign, List<int[]> top, int K, Vectorizer vec, String[] labels, boolean labeled) {
        out("\n--- " + name + " ---");
        if (labeled) out("Adjusted Rand Index vs annotated labels: " + f(Metrics.ari(labels, assign)));
        out("Topic diversity (top-10 words): " + f(Metrics.topicDiversity(top)));
        out("NPMI coherence (C_v proxy):     " + f(Metrics.npmiCoherence(top, vec.docs)));
        for (int k = 0; k < K; k++) {
            int size = 0;
            Map<String, Integer> lc = new HashMap<>();
            for (int i = 0; i < assign.length; i++) if (assign[i] == k) { size++; lc.merge(labels[i], 1, Integer::sum); }
            String maj = "-"; int mc = 0;
            for (var e : lc.entrySet()) if (e.getValue() > mc) { mc = e.getValue(); maj = e.getKey(); }
            String lab = labeled && size > 0 ? String.format(Locale.ROOT, " majority=%s purity=%s", maj, f((double) mc / size)) : "";
            out(String.format(Locale.ROOT, "  topic %d (n=%d)%s: %s", k, size, lab, words(vec, top.get(k))));
        }
    }

    private static void evalSplit(String name, int[] train, int[] test, Vectorizer vec, String[] labels, List<String> classes) {
        NaiveBayes nb = new NaiveBayes(vec.docs, labels, train, vec.size(), classes);
        Map<String, Integer> cnt = new HashMap<>();
        for (int i : train) cnt.merge(labels[i], 1, Integer::sum);
        String majority = Collections.max(cnt.entrySet(), Map.Entry.comparingByValue()).getKey();
        String[] gold = new String[test.length], pNb = new String[test.length], pMaj = new String[test.length];
        for (int i = 0; i < test.length; i++) {
            gold[i] = labels[test[i]];
            pNb[i] = nb.predict(vec.docs[test[i]]);
            pMaj[i] = majority;
        }
        Map<String, Metrics.PRF> rNb = Metrics.classReport(gold, pNb, classes);
        Map<String, Metrics.PRF> rMaj = Metrics.classReport(gold, pMaj, classes);
        out("\n" + name + "  (train=" + train.length + ", test=" + test.length + ")");
        out("  Majority baseline : accuracy=" + f(Metrics.accuracy(gold, pMaj)) + " macro-F1=" + f(rMaj.get("macro").f1()));
        out("  Naive Bayes       : accuracy=" + f(Metrics.accuracy(gold, pNb)) + " macro-F1=" + f(rNb.get("macro").f1()));
        for (String c : classes)
            out(String.format(Locale.ROOT, "    %-22s P=%s R=%s F1=%s", c, f(rNb.get(c).precision()), f(rNb.get(c).recall()), f(rNb.get(c).f1())));
    }

    private static double[][] monthlyShares(int[] assign, int K, TreeMap<YearMonth, List<Integer>> byMonth) {
        double[][] s = new double[byMonth.size()][K];
        int m = 0;
        for (List<Integer> ids : byMonth.values()) {
            for (int i : ids) s[m][assign[i]]++;
            for (int k = 0; k < K; k++) s[m][k] /= ids.size();
            m++;
        }
        return s;
    }

    private static double meanJs(double[][] shares) {
        if (shares.length < 2) return 0;
        double t = 0;
        for (int i = 1; i < shares.length; i++) t += Metrics.js(shares[i - 1], shares[i]);
        return t / (shares.length - 1);
    }

    /** Terms occurring in at least two public advisory / CTI report documents. */
    private static Set<String> loadPublicTerms(Path p) throws IOException {
        Set<String> terms = new HashSet<>();
        if (!Files.exists(p)) return terms;
        Map<String, Integer> df = new HashMap<>();
        for (Doc d : DataLoader.loadCorpus(p)) {
            String prepared = Preprocessor.redactPii(Preprocessor.refang(d.text()));
            for (String w : new HashSet<>(Preprocessor.tokenize(IocExtractor.strip(prepared)))) df.merge(w, 1, Integer::sum);
        }
        for (var e : df.entrySet()) if (e.getValue() >= 2) terms.add(e.getKey());
        return terms;
    }

    private static String sha256(Path p) throws Exception {
        byte[] h = MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(p));
        StringBuilder sb = new StringBuilder();
        for (byte b : h) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    // ===================== Data model =====================
    /** One text record from the corpus (e.g. a forum post or an advisory). */
    record Doc(String id, LocalDate date, String source, String label, String text) {}
    /** An indicator of compromise: a type (ipv4, url, domain, md5, sha1, sha256, cve) and a normalised value. */
    record Ioc(String type, String value) {
        @Override public String toString() { return type + ":" + value; }
    }

    // ===================== Pipeline modules =====================
    /** Minimal dependency-free CSV loading for the corpus and the IOC gold annotations. */
    static final class DataLoader {
        private DataLoader() {}

        /** Expected header: id,date,source,label,text  (date = yyyy-MM-dd; label may be empty). */
        public static List<Doc> loadCorpus(Path path) throws IOException {
            List<List<String>> rows = parseCsv(Files.readString(path, StandardCharsets.UTF_8));
            if (rows.isEmpty()) throw new IOException("Empty CSV: " + path);
            Map<String, Integer> h = header(rows.get(0));
            List<Doc> docs = new ArrayList<>();
            for (int i = 1; i < rows.size(); i++) {
                List<String> r = rows.get(i);
                if (r.size() < h.size()) continue;
                docs.add(new Doc(
                        r.get(h.get("id")).trim(),
                        LocalDate.parse(r.get(h.get("date")).trim()),
                        r.get(h.get("source")).trim(),
                        r.get(h.get("label")).trim(),
                        r.get(h.get("text"))));
            }
            return docs;
        }

        /** Expected header: doc_id,type,value. Returns gold IOCs per document id. */
        public static Map<String, Set<Ioc>> loadGold(Path path) throws IOException {
            List<List<String>> rows = parseCsv(Files.readString(path, StandardCharsets.UTF_8));
            Map<String, Integer> h = header(rows.get(0));
            Map<String, Set<Ioc>> gold = new HashMap<>();
            for (int i = 1; i < rows.size(); i++) {
                List<String> r = rows.get(i);
                if (r.size() < 3) continue;
                gold.computeIfAbsent(r.get(h.get("doc_id")).trim(), k -> new LinkedHashSet<>())
                    .add(new Ioc(r.get(h.get("type")).trim().toLowerCase(), r.get(h.get("value")).trim().toLowerCase()));
            }
            return gold;
        }

        private static Map<String, Integer> header(List<String> row) {
            Map<String, Integer> h = new HashMap<>();
            for (int i = 0; i < row.size(); i++) h.put(row.get(i).trim().toLowerCase().replace("\uFEFF", ""), i);
            return h;
        }

        /** RFC-4180 style parser: quoted fields, escaped quotes (""), embedded commas and newlines. */
        static List<List<String>> parseCsv(String s) {
            List<List<String>> rows = new ArrayList<>();
            List<String> row = new ArrayList<>();
            StringBuilder f = new StringBuilder();
            boolean quoted = false;
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                if (quoted) {
                    if (c == '"') {
                        if (i + 1 < s.length() && s.charAt(i + 1) == '"') { f.append('"'); i++; }
                        else quoted = false;
                    } else f.append(c);
                } else if (c == '"') quoted = true;
                else if (c == ',') { row.add(f.toString()); f.setLength(0); }
                else if (c == '\n' || c == '\r') {
                    if (c == '\r' && i + 1 < s.length() && s.charAt(i + 1) == '\n') i++;
                    row.add(f.toString()); f.setLength(0);
                    if (!(row.size() == 1 && row.get(0).isEmpty())) rows.add(row);
                    row = new ArrayList<>();
                } else f.append(c);
            }
            if (f.length() > 0 || !row.isEmpty()) { row.add(f.toString()); rows.add(row); }
            return rows;
        }
    }

    /** Privacy-conscious text preparation: de-fanging, PII redaction, tokenisation. */
    static final class Preprocessor {
        private Preprocessor() {}

        private static final Pattern EMAIL = Pattern.compile("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}");
        private static final Pattern HANDLE = Pattern.compile("(?<![\\w])@[A-Za-z0-9_]{4,}");
        private static final Pattern WORD = Pattern.compile("[a-z]{3,}");
        static final String PII_TOKEN = "piiredacted";

        private static final Set<String> STOP = new HashSet<>(Arrays.asList((
            "the,and,for,with,that,this,are,was,were,from,have,has,had,not,but,all,can,will,you,your,our,their,they,them,"
          + "its,out,new,now,any,per,via,more,most,also,into,than,then,there,here,been,being,only,each,other,such,these,"
          + "those,who,what,when,where,which,while,about,over,under,after,before,between,through,both,some,one,two,"
          + "get,got,use,used,using,may,must,should,would,could,every,much,many,very,just,too,etc,ones,own,same,"
          + "contact,details,price,visit,order,update,updated,version,client,required,observed,hosted,reported,"
          + "sample,hash,builder,md,seller,vendor," + PII_TOKEN).split(",")));

        /** Reverse common "defanging" (hxxp, [.], (.), [:]) so indicators can be recognised. */
        public static String refang(String s) {
            return s.replaceAll("(?i)hxxp", "http").replace("[.]", ".").replace("(.)", ".")
                    .replace("[:]", ":").replace("[://]", "://");
        }

        /** Replace e-mail addresses and @handles with a neutral placeholder before any analysis. */
        public static String redactPii(String s) {
            return HANDLE.matcher(EMAIL.matcher(s).replaceAll(" " + PII_TOKEN + " ")).replaceAll(" " + PII_TOKEN + " ");
        }

        public static int countPii(String s) {
            int n = 0;
            Matcher m = EMAIL.matcher(s); while (m.find()) n++;
            m = HANDLE.matcher(EMAIL.matcher(s).replaceAll(" ")); while (m.find()) n++;
            return n;
        }

        /** Lower-case alphabetic tokens (length >= 3) without stop words. */
        public static List<String> tokenize(String s) {
            List<String> out = new ArrayList<>();
            Matcher m = WORD.matcher(s.toLowerCase(Locale.ROOT));
            while (m.find()) if (!STOP.contains(m.group())) out.add(m.group());
            return out;
        }
    }

    /** Rule-based IOC extraction (the "entity extraction" baseline). Input should already be de-fanged and PII-redacted. */
    static final class IocExtractor {
        private IocExtractor() {}

        private static final Pattern URL = Pattern.compile("\\bhttps?://[^\\s<>\"']+", Pattern.CASE_INSENSITIVE);
        private static final Pattern SHA256 = Pattern.compile("\\b[a-fA-F0-9]{64}\\b");
        private static final Pattern SHA1 = Pattern.compile("\\b[a-fA-F0-9]{40}\\b");
        private static final Pattern MD5 = Pattern.compile("\\b[a-fA-F0-9]{32}\\b");
        private static final Pattern CVE = Pattern.compile("\\bCVE-\\d{4}-\\d{4,7}\\b", Pattern.CASE_INSENSITIVE);
        private static final Pattern IPV4 = Pattern.compile(
                "\\b(?:(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\b");
        private static final Pattern DOMAIN = Pattern.compile(
                "\\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+(?:com|net|org|io|ru|cn|info|biz|xyz|top|onion|co|cc|tk|su|site|online)\\b",
                Pattern.CASE_INSENSITIVE);

        private static final Object[][] ORDERED = {
            {"url", URL}, {"sha256", SHA256}, {"sha1", SHA1}, {"md5", MD5}, {"cve", CVE}, {"ipv4", IPV4}, {"domain", DOMAIN}
        };

        /** Extract IOCs. Each match is blanked out before the next pattern runs, so a domain inside a URL is not double counted. */
        public static Set<Ioc> extract(String text) {
            Set<Ioc> found = new LinkedHashSet<>();
            String work = text;
            for (Object[] p : ORDERED) {
                String type = (String) p[0];
                Matcher m = ((Pattern) p[1]).matcher(work);
                StringBuilder sb = new StringBuilder();
                while (m.find()) {
                    String v = m.group();
                    if (type.equals("url")) v = v.replaceAll("[.,;:)\\]]+$", "");
                    found.add(new Ioc(type, v.toLowerCase(Locale.ROOT)));
                    m.appendReplacement(sb, " ");
                }
                m.appendTail(sb);
                work = sb.toString();
            }
            return found;
        }

        /** Remove every IOC-like string so hashes, IPs and URLs do not pollute topic models. */
        public static String strip(String text) {
            String work = text;
            for (Object[] p : ORDERED) work = ((Pattern) p[1]).matcher(work).replaceAll(" ");
            return work;
        }
    }

    /** Builds the vocabulary, token-id sequences (for LDA / Naive Bayes) and L2-normalised TF-IDF vectors (for K-means). */
    static final class Vectorizer {
        public final List<String> vocab;
        public final Map<String, Integer> index = new HashMap<>();
        public final int[][] docs;      // token ids per document (after vocabulary filtering)
        public final double[][] tfidf;  // dense, L2-normalised
        public final int[] df;

        public Vectorizer(List<List<String>> tokens, int minDf, double maxDfRatio) {
            int n = tokens.size();
            Map<String, Integer> dfMap = new HashMap<>();
            for (List<String> t : tokens) for (String w : new HashSet<>(t)) dfMap.merge(w, 1, Integer::sum);
            List<String> terms = new ArrayList<>();
            for (var e : dfMap.entrySet())
                if (e.getValue() >= minDf && e.getValue() <= maxDfRatio * n) terms.add(e.getKey());
            Collections.sort(terms);
            vocab = Collections.unmodifiableList(terms);
            for (int i = 0; i < vocab.size(); i++) index.put(vocab.get(i), i);
            df = new int[vocab.size()];
            for (int i = 0; i < vocab.size(); i++) df[i] = dfMap.get(vocab.get(i));

            docs = new int[n][];
            tfidf = new double[n][vocab.size()];
            for (int d = 0; d < n; d++) {
                List<Integer> ids = new ArrayList<>();
                for (String w : tokens.get(d)) { Integer id = index.get(w); if (id != null) ids.add(id); }
                docs[d] = ids.stream().mapToInt(Integer::intValue).toArray();
                int[] tf = new int[vocab.size()];
                for (int id : docs[d]) tf[id]++;
                double norm = 0;
                for (int j = 0; j < tf.length; j++) {
                    if (tf[j] == 0) continue;
                    double idf = Math.log((1.0 + n) / (1.0 + df[j])) + 1.0;
                    tfidf[d][j] = (1.0 + Math.log(tf[j])) * idf;
                    norm += tfidf[d][j] * tfidf[d][j];
                }
                norm = Math.sqrt(norm);
                if (norm > 0) for (int j = 0; j < tf.length; j++) tfidf[d][j] /= norm;
            }
        }

        public int size() { return vocab.size(); }
    }

    /** Spherical K-means (cosine similarity) with k-means++ seeding and several restarts. Expects L2-normalised rows. */
    static final class KMeans {
        public final int[] assign;
        public final double[][] centroids;
        public final double score; // sum of cosine similarities to assigned centroids (higher = tighter)

        private KMeans(int[] a, double[][] c, double s) { assign = a; centroids = c; score = s; }

        public static KMeans fit(double[][] x, int k, long seed, int restarts) {
            KMeans best = null;
            for (int r = 0; r < restarts; r++) {
                KMeans cur = runOnce(x, k, new Random(seed + 1000L * r));
                if (best == null || cur.score > best.score) best = cur;
            }
            return best;
        }

        private static KMeans runOnce(double[][] x, int k, Random rnd) {
            int n = x.length, v = x[0].length;
            double[][] c = new double[k][];
            c[0] = x[rnd.nextInt(n)].clone();
            for (int j = 1; j < k; j++) {
                double[] dist = new double[n]; double sum = 0;
                for (int i = 0; i < n; i++) {
                    double best = -1;
                    for (int q = 0; q < j; q++) best = Math.max(best, dot(x[i], c[q]));
                    dist[i] = 1 - best; sum += dist[i];
                }
                int pick = rnd.nextInt(n);
                if (sum > 0) {
                    double t = rnd.nextDouble() * sum, acc = 0;
                    for (int i = 0; i < n; i++) { acc += dist[i]; if (acc >= t) { pick = i; break; } }
                }
                c[j] = x[pick].clone();
            }
            int[] a = new int[n]; Arrays.fill(a, -1);
            for (int iter = 0; iter < 100; iter++) {
                boolean changed = false;
                for (int i = 0; i < n; i++) {
                    int bj = 0; double bs = -2;
                    for (int j = 0; j < k; j++) { double s = dot(x[i], c[j]); if (s > bs) { bs = s; bj = j; } }
                    if (a[i] != bj) { a[i] = bj; changed = true; }
                }
                if (!changed) break;
                double[][] nc = new double[k][v]; int[] cnt = new int[k];
                for (int i = 0; i < n; i++) { cnt[a[i]]++; for (int j = 0; j < v; j++) nc[a[i]][j] += x[i][j]; }
                for (int j = 0; j < k; j++) {
                    if (cnt[j] == 0) { nc[j] = x[rnd.nextInt(n)].clone(); continue; }
                    double nm = Math.sqrt(dot(nc[j], nc[j]));
                    if (nm > 0) for (int q = 0; q < v; q++) nc[j][q] /= nm;
                }
                c = nc;
            }
            double score = 0;
            for (int i = 0; i < n; i++) score += dot(x[i], c[a[i]]);
            return new KMeans(a, c, score);
        }

        static double dot(double[] a, double[] b) { double s = 0; for (int i = 0; i < a.length; i++) s += a[i] * b[i]; return s; }

        /** Indices of the {@code n} highest-weighted terms of a centroid. */
        public int[] topTerms(int cluster, int n) {
            Integer[] idx = new Integer[centroids[cluster].length];
            for (int i = 0; i < idx.length; i++) idx[i] = i;
            Arrays.sort(idx, (p, q) -> Double.compare(centroids[cluster][q], centroids[cluster][p]));
            int[] out = new int[Math.min(n, idx.length)];
            for (int i = 0; i < out.length; i++) out[i] = idx[i];
            return out;
        }
    }

    /** Latent Dirichlet Allocation trained with collapsed Gibbs sampling (fixed seed => reproducible). */
    static final class Lda {
        public final int topics, vocabSize;
        public final double[][] theta; // doc-topic distribution
        public final double[][] phi;   // topic-word distribution

        public Lda(int[][] docs, int vocabSize, int topics, double alpha, double beta, int iterations, long seed) {
            this.topics = topics; this.vocabSize = vocabSize;
            Random rnd = new Random(seed);
            int n = docs.length;
            int[][] z = new int[n][];
            int[][] ndk = new int[n][topics];
            int[][] nkw = new int[topics][vocabSize];
            int[] nk = new int[topics];
            for (int d = 0; d < n; d++) {
                z[d] = new int[docs[d].length];
                for (int i = 0; i < docs[d].length; i++) {
                    int t = rnd.nextInt(topics);
                    z[d][i] = t; ndk[d][t]++; nkw[t][docs[d][i]]++; nk[t]++;
                }
            }
            double[] p = new double[topics];
            for (int it = 0; it < iterations; it++) {
                for (int d = 0; d < n; d++) {
                    for (int i = 0; i < docs[d].length; i++) {
                        int w = docs[d][i], t = z[d][i];
                        ndk[d][t]--; nkw[t][w]--; nk[t]--;
                        double sum = 0;
                        for (int k = 0; k < topics; k++) {
                            p[k] = (ndk[d][k] + alpha) * (nkw[k][w] + beta) / (nk[k] + vocabSize * beta);
                            sum += p[k];
                        }
                        double u = rnd.nextDouble() * sum, acc = 0;
                        int nt = topics - 1;
                        for (int k = 0; k < topics; k++) { acc += p[k]; if (acc >= u) { nt = k; break; } }
                        z[d][i] = nt; ndk[d][nt]++; nkw[nt][w]++; nk[nt]++;
                    }
                }
            }
            theta = new double[n][topics];
            for (int d = 0; d < n; d++) {
                double tot = docs[d].length + topics * alpha;
                for (int k = 0; k < topics; k++) theta[d][k] = (ndk[d][k] + alpha) / tot;
            }
            phi = new double[topics][vocabSize];
            for (int k = 0; k < topics; k++)
                for (int w = 0; w < vocabSize; w++) phi[k][w] = (nkw[k][w] + beta) / (nk[k] + vocabSize * beta);
        }

        public int[] dominantTopics() {
            int[] a = new int[theta.length];
            for (int d = 0; d < a.length; d++) {
                int b = 0;
                for (int k = 1; k < topics; k++) if (theta[d][k] > theta[d][b]) b = k;
                a[d] = b;
            }
            return a;
        }

        public int[] topTerms(int topic, int n) {
            Integer[] idx = new Integer[vocabSize];
            for (int i = 0; i < vocabSize; i++) idx[i] = i;
            Arrays.sort(idx, (a, b) -> Double.compare(phi[topic][b], phi[topic][a]));
            int[] out = new int[Math.min(n, vocabSize)];
            for (int i = 0; i < out.length; i++) out[i] = idx[i];
            return out;
        }
    }

    /** Multinomial Naive Bayes with Laplace smoothing - the supervised classification baseline. */
    static final class NaiveBayes {
        private final List<String> classes;
        private final double[] logPrior;
        private final double[][] logLik;

        public NaiveBayes(int[][] docs, String[] labels, int[] trainIdx, int vocab, List<String> classes) {
            this.classes = classes;
            int c = classes.size();
            double[] cnt = new double[c];
            double[][] wc = new double[c][vocab];
            double[] tot = new double[c];
            for (int i : trainIdx) {
                int k = classes.indexOf(labels[i]);
                cnt[k]++;
                for (int w : docs[i]) { wc[k][w]++; tot[k]++; }
            }
            logPrior = new double[c];
            logLik = new double[c][vocab];
            for (int k = 0; k < c; k++) {
                logPrior[k] = Math.log((cnt[k] + 1) / (trainIdx.length + c));
                for (int w = 0; w < vocab; w++) logLik[k][w] = Math.log((wc[k][w] + 1) / (tot[k] + vocab));
            }
        }

        public String predict(int[] doc) {
            int best = 0; double bs = Double.NEGATIVE_INFINITY;
            for (int k = 0; k < classes.size(); k++) {
                double s = logPrior[k];
                for (int w : doc) s += logLik[k][w];
                if (s > bs) { bs = s; best = k; }
            }
            return classes.get(best);
        }
    }

    /** Evaluation metrics named in the proposal: ARI, topic diversity, NPMI coherence, P/R/F1, temporal stability (JS). */
    static final class Metrics {
        private Metrics() {}

        public record PRF(double precision, double recall, double f1) {
            static PRF of(int tp, int fp, int fn) {
                double p = tp + fp == 0 ? 0 : (double) tp / (tp + fp);
                double r = tp + fn == 0 ? 0 : (double) tp / (tp + fn);
                return new PRF(p, r, p + r == 0 ? 0 : 2 * p * r / (p + r));
            }
        }

        /** Adjusted Rand Index between gold labels and cluster assignments. */
        public static double ari(String[] gold, int[] clusters) {
            int n = gold.length;
            Map<String, Integer> g = new HashMap<>();
            for (String s : gold) g.putIfAbsent(s, g.size());
            int kc = Arrays.stream(clusters).max().orElse(0) + 1;
            long[][] m = new long[g.size()][kc];
            for (int i = 0; i < n; i++) m[g.get(gold[i])][clusters[i]]++;
            double index = 0, sa = 0, sb = 0;
            long[] colSum = new long[kc];
            for (long[] row : m) {
                long rs = 0;
                for (int j = 0; j < kc; j++) { index += c2(row[j]); rs += row[j]; colSum[j] += row[j]; }
                sa += c2(rs);
            }
            for (long cs : colSum) sb += c2(cs);
            double expected = sa * sb / c2(n), max = (sa + sb) / 2;
            return max == expected ? 1.0 : (index - expected) / (max - expected);
        }

        private static double c2(long x) { return x * (x - 1) / 2.0; }

        /** Fraction of unique words among all topics' top-N words (1.0 = no overlap between topics). */
        public static double topicDiversity(List<int[]> topWords) {
            Set<Integer> uniq = new HashSet<>(); int total = 0;
            for (int[] t : topWords) for (int w : t) { uniq.add(w); total++; }
            return total == 0 ? 0 : (double) uniq.size() / total;
        }

        /** Mean NPMI coherence over word pairs using document co-occurrence (a fast proxy for C_v). */
        public static double npmiCoherence(List<int[]> topWords, int[][] docs) {
            int n = docs.length;
            Map<Integer, BitSet> occ = new HashMap<>();
            for (int[] t : topWords) for (int w : t) occ.putIfAbsent(w, new BitSet(n));
            for (int d = 0; d < n; d++) for (int w : docs[d]) { BitSet b = occ.get(w); if (b != null) b.set(d); }
            double total = 0; int pairs = 0;
            for (int[] t : topWords) {
                for (int i = 0; i < t.length; i++) for (int j = i + 1; j < t.length; j++) {
                    BitSet a = occ.get(t[i]), b = occ.get(t[j]);
                    BitSet and = (BitSet) a.clone(); and.and(b);
                    double pi = (double) a.cardinality() / n, pj = (double) b.cardinality() / n, pij = (double) and.cardinality() / n;
                    double npmi;
                    if (pij == 0) npmi = -1;
                    else if (pij >= 1) npmi = 1;
                    else npmi = Math.log(pij / (pi * pj)) / -Math.log(pij);
                    total += npmi; pairs++;
                }
            }
            return pairs == 0 ? 0 : total / pairs;
        }

        /** Jensen-Shannon divergence (base 2, range 0..1). */
        public static double js(double[] p, double[] q) {
            double d = 0;
            for (int i = 0; i < p.length; i++) {
                double m = (p[i] + q[i]) / 2;
                if (p[i] > 0) d += 0.5 * p[i] * Math.log(p[i] / m) / Math.log(2);
                if (q[i] > 0) d += 0.5 * q[i] * Math.log(q[i] / m) / Math.log(2);
            }
            return d;
        }

        public static double accuracy(String[] gold, String[] pred) {
            int ok = 0;
            for (int i = 0; i < gold.length; i++) if (gold[i].equals(pred[i])) ok++;
            return gold.length == 0 ? 0 : (double) ok / gold.length;
        }

        /** Per-class P/R/F1 plus macro-F1 (key "macro"). */
        public static Map<String, PRF> classReport(String[] gold, String[] pred, List<String> classes) {
            Map<String, PRF> out = new LinkedHashMap<>();
            double f = 0, p = 0, r = 0;
            for (String c : classes) {
                int tp = 0, fp = 0, fn = 0;
                for (int i = 0; i < gold.length; i++) {
                    boolean g = gold[i].equals(c), q = pred[i].equals(c);
                    if (g && q) tp++; else if (!g && q) fp++; else if (g) fn++;
                }
                PRF m = PRF.of(tp, fp, fn);
                out.put(c, m); f += m.f1(); p += m.precision(); r += m.recall();
            }
            int k = classes.size();
            out.put("macro", new PRF(p / k, r / k, f / k));
            return out;
        }
    }

    // =====================================================================================
    // SampleData: generates the synthetic sample corpus, IOC gold file and public-report corpus
    // (only when the files are missing). Uses documentation IP ranges and example.* domains.
    // =====================================================================================
    static final class SampleData {
        private SampleData() {}

        private static final Map<String, String[]> CATS = new LinkedHashMap<>();
        static {
            CATS.put("ransomware_affiliate", new String[]{
                "Ransomware-as-a-service program is recruiting affiliates. Revenue split {s} percent for the affiliate, negotiation panel and leak site included.",
                "New ransomware group opens affiliate program, seeking experienced pentesters. Affiliate keeps {s} percent of each ransom payment, support chat provided.",
                "Affiliate programme update: new encryptor build, faster encryption, improved negotiation portal and data leak blog. Only vetted partners accepted."});
            CATS.put("credential_leak", new String[]{
                "Fresh combo list with {n}k email and password pairs from a retail breach. Sample available, checked for validity, cheap price.",
                "Selling database dump from a hosting company, {n}k user records with hashed passwords. Proof shared with trusted buyers using escrow.",
                "Credential dump posted, {n}k accounts from a gaming platform. Combo checker results included, updated daily."});
            CATS.put("initial_access", new String[]{
                "Selling VPN access to a {sec} company, revenue around {n} million, domain admin privileges. Price negotiable via escrow.",
                "Initial access broker offering RDP access to a {sec} network, antivirus present, {n} hosts visible. Auction starts tomorrow.",
                "Access for sale: corporate network in the {sec} sector, privileged account, backups reachable. Contact for details."});
            CATS.put("ddos_service", new String[]{
                "Stresser service with layer 7 and layer 4 attack capacity, hourly and monthly plans, crypto payment accepted.",
                "Booter panel relaunched, new botnet capacity of {n} gbps, free test attack for new customers, uptime guaranteed.",
                "DDoS for hire, reliable bypass for common protection, support available all day, cheap daily packages."});
            CATS.put("phishing_kit", new String[]{
                "Phishing kit for bank login pages with anti-bot cloaking and admin panel, new templates added every week.",
                "Selling phishing pages for {sec} brands, mobile friendly, OTP interception module, installation help included.",
                "Updated phishing kit with live panel, redirect rules and sms lure templates. Buyers receive free updates for a month."});
            CATS.put("malware_loader", new String[]{
                "Infostealer logs subscription, fresh logs daily from loader campaigns, browser cookies and wallet data, monthly plans.",
                "New loader and crypter offered, low detection rate, build updates weekly, panel with statistics and task management.",
                "Malware-as-a-service stealer updated, new builder, improved evasion and clipboard module, subscription tiers available."});
        }
        private static final String[] SECTORS = {"healthcare", "manufacturing", "education", "logistics", "finance", "retail", "energy"};
        private static final String[] SOURCES = {"forum_alpha", "forum_beta", "market_gamma", "channel_delta"};
        private static final String[] PUBLIC = {
            "Advisory: threat actors continue to target organizations with ransomware, using phishing emails and exploitation of unpatched vulnerabilities. Apply patches, enable multifactor authentication and maintain offline backups.",
            "Report: credential theft campaigns rely on phishing and infostealer malware. Organizations should monitor for leaked credentials, enforce multifactor authentication and review remote access logs.",
            "Security bulletin: distributed denial of service attacks remain a risk for online services. Operators should use traffic filtering, rate limiting and coordinate with upstream providers.",
            "Threat report: ransomware operators gained network access through exposed remote desktop services and vulnerable VPN appliances. Defenders should restrict remote access and patch promptly.",
            "Advisory: malware loaders deliver additional payloads after initial infection. Endpoint detection, application allowlisting and user awareness training reduce exposure.",
            "Report: phishing campaigns impersonate financial institutions to harvest credentials. Banks and users should adopt phishing resistant authentication and report suspicious messages."};

        private static String hex(Random r, int len) {
            StringBuilder sb = new StringBuilder();
            while (sb.length() < len) sb.append(Integer.toHexString(r.nextInt(16)));
            return sb.toString();
        }

        private static String q(String s) { return "\"" + s.replace("\"", "\"\"") + "\""; }

        private static void write(Path p, List<String[]> rows) throws IOException {
            Path parent = p.toAbsolutePath().getParent();
            if (parent != null) Files.createDirectories(parent);
            StringBuilder sb = new StringBuilder();
            for (String[] r : rows) {
                for (int i = 0; i < r.length; i++) sb.append(i == 0 ? "" : ",").append(q(r[i]));
                sb.append('\n');
            }
            Files.writeString(p, sb.toString(), StandardCharsets.UTF_8);
        }

        static void ensure(Path dataP, Path pubP, Path goldP) throws IOException {
            if (!Files.exists(dataP)) {
                Random rnd = new Random(7);
                List<String> names = new ArrayList<>(CATS.keySet());
                List<String[]> rows = new ArrayList<>();
                List<String[]> gold = new ArrayList<>();
                rows.add(new String[]{"id", "date", "source", "label", "text"});
                gold.add(new String[]{"doc_id", "type", "value"});
                int did = 0;
                for (int mi = 0; mi < 16; mi++) {
                    int y = 2025 + (6 + mi) / 12, m = (6 + mi) % 12 + 1;
                    double t = mi / 15.0;
                    double[] w = {1.0, 1.2 - 0.3 * t, 0.6 + 1.6 * t, 1.6 - 1.4 * t, 1.0, 0.8 + 0.8 * t};
                    double wsum = 0; for (double x : w) wsum += x;
                    for (int j = 0; j < 15; j++) {
                        double u = rnd.nextDouble() * wsum, acc = 0; int ci = names.size() - 1;
                        for (int c = 0; c < w.length; c++) { acc += w[c]; if (acc >= u) { ci = c; break; } }
                        String cat = names.get(ci);
                        String[] tpl = CATS.get(cat);
                        String text = tpl[rnd.nextInt(tpl.length)]
                                .replace("{s}", String.valueOf(new int[]{70, 75, 80, 85}[rnd.nextInt(4)]))
                                .replace("{n}", String.valueOf(2 + rnd.nextInt(89)))
                                .replace("{sec}", SECTORS[rnd.nextInt(SECTORS.length)]);
                        String id = String.format("D%04d", ++did);
                        List<String[]> g = new ArrayList<>();
                        if (rnd.nextDouble() < 0.25) {
                            String ip = new String[]{"192.0.2", "198.51.100", "203.0.113"}[rnd.nextInt(3)] + "." + (1 + rnd.nextInt(254));
                            text += " Control server observed at " + ip + "."; g.add(new String[]{id, "ipv4", ip});
                        }
                        if (rnd.nextDouble() < 0.25) {
                            String sub = "panel-" + hex(rnd, 4);
                            text += " Panel hosted at hxxp://" + sub + "[.]example[.]com/login for customers.";
                            g.add(new String[]{id, "url", "http://" + sub + ".example.com/login"});
                        }
                        if (rnd.nextDouble() < 0.20) {
                            String d = "shop-" + hex(rnd, 4) + ".example.net";
                            text += " Visit " + d + " to order."; g.add(new String[]{id, "domain", d});
                        }
                        if (rnd.nextDouble() < 0.15) {
                            String x = hex(rnd, 64); text += " Sample hash " + x + "."; g.add(new String[]{id, "sha256", x});
                        }
                        if (rnd.nextDouble() < 0.10) {
                            String x = hex(rnd, 32); text += " Builder md5 " + x + "."; g.add(new String[]{id, "md5", x});
                        }
                        if (rnd.nextDouble() < 0.15 && (cat.equals("initial_access") || cat.equals("ransomware_affiliate") || cat.equals("malware_loader"))) {
                            String cv = "CVE-" + new int[]{2023, 2024, 2025, 2026}[rnd.nextInt(4)] + "-" + (1000 + rnd.nextInt(48999));
                            text += " Reported entry via " + cv + "."; g.add(new String[]{id, "cve", cv.toLowerCase(Locale.ROOT)});
                        }
                        if (rnd.nextDouble() < 0.30) text += " Contact seller" + (100 + rnd.nextInt(900)) + "@mail.example.org or @vendor_" + hex(rnd, 4) + " for details.";
                        if (rnd.nextDouble() < 0.04) text += " Client version 10.0.19045.1 required.";
                        String date = LocalDate.of(y, m, 1 + rnd.nextInt(28)).toString();
                        rows.add(new String[]{id, date, SOURCES[rnd.nextInt(SOURCES.length)], cat, text});
                        gold.addAll(g);
                    }
                }
                for (int i = 0; i < 6; i++) {
                    String[] src = rows.get(1 + rnd.nextInt(rows.size() - 1));
                    rows.add(new String[]{String.format("D%04d", ++did), src[1], src[2], src[3], src[4]});
                }
                write(dataP, rows);
                write(goldP, gold);
                System.out.println("[sample data] generated " + dataP + " and " + goldP);
            }
            if (!Files.exists(pubP)) {
                List<String[]> rows = new ArrayList<>();
                rows.add(new String[]{"id", "date", "source", "label", "text"});
                for (int i = 0; i < 36; i++)
                    rows.add(new String[]{String.format("P%03d", i + 1),
                            LocalDate.of(2025 + (6 + i / 3) / 12, (6 + i / 3) % 12 + 1, 10).toString(),
                            "public_advisory", "", PUBLIC[i % 6] + " Update " + (i + 1) + "."});
                write(pubP, rows);
                System.out.println("[sample data] generated " + pubP);
            }
        }
    }

}