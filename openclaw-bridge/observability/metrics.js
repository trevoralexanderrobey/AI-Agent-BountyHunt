const HISTOGRAM_BUCKETS = Object.freeze([10, 50, 100, 250, 500, 1000, 2500, 5000, 10000, Infinity]);

function createMetrics() {
  const counters = new Map();
  const gauges = new Map();
  const histograms = new Map();

  function normalizeName(rawName) {
    if (typeof rawName !== "string") {
      return "";
    }
    const name = rawName.trim();
    return name.length > 0 ? name : "";
  }

  function normalizeLabels(rawLabels) {
    if (!rawLabels || typeof rawLabels !== "object" || Array.isArray(rawLabels)) {
      return {
        labels: {},
        labelKey: "",
      };
    }

    const keys = Object.keys(rawLabels).sort();
    const labels = {};
    const parts = [];

    for (const key of keys) {
      if (typeof key !== "string" || key.length === 0) {
        continue;
      }
      const value = rawLabels[key];
      if (typeof value === "undefined") {
        continue;
      }
      const normalizedValue = String(value);
      labels[key] = normalizedValue;
      parts.push(`${key}=${normalizedValue}`);
    }

    return {
      labels,
      labelKey: parts.join("|"),
    };
  }

  function makeMetricKey(name, labelKey) {
    return labelKey ? `${name}|${labelKey}` : name;
  }

  function withGuard(fn) {
    try {
      return fn();
    } catch {
      return undefined;
    }
  }

  function compareEntries(a, b) {
    if (a.name !== b.name) {
      return a.name.localeCompare(b.name);
    }
    return a.labelKey.localeCompare(b.labelKey);
  }

  function increment(counterName, labels) {
    return withGuard(() => {
      const name = normalizeName(counterName);
      if (!name) {
        return;
      }

      const normalized = normalizeLabels(labels);
      const key = makeMetricKey(name, normalized.labelKey);
      const entry = counters.get(key);

      if (entry) {
        entry.value += 1;
        return;
      }

      counters.set(key, {
        name,
        labels: normalized.labels,
        labelKey: normalized.labelKey,
        value: 1,
      });
    });
  }

  function observe(histogramName, rawValue, labels) {
    return withGuard(() => {
      const name = normalizeName(histogramName);
      const value = Number(rawValue);
      if (!name || !Number.isFinite(value) || value < 0) {
        return;
      }

      const normalized = normalizeLabels(labels);
      const key = makeMetricKey(name, normalized.labelKey);
      let entry = histograms.get(key);

      if (!entry) {
        entry = {
          name,
          labels: normalized.labels,
          labelKey: normalized.labelKey,
          count: 0,
          sum: 0,
          bucketCounts: new Array(HISTOGRAM_BUCKETS.length).fill(0),
        };
        histograms.set(key, entry);
      }

      entry.count += 1;
      entry.sum += value;

      for (let i = 0; i < HISTOGRAM_BUCKETS.length; i += 1) {
        if (value <= HISTOGRAM_BUCKETS[i]) {
          entry.bucketCounts[i] += 1;
        }
      }
    });
  }

  function gauge(name, rawValue, labels) {
    return withGuard(() => {
      const normalizedName = normalizeName(name);
      const value = Number(rawValue);
      if (!normalizedName || !Number.isFinite(value)) {
        return;
      }

      const normalized = normalizeLabels(labels);
      const key = makeMetricKey(normalizedName, normalized.labelKey);

      gauges.set(key, {
        name: normalizedName,
        labels: normalized.labels,
        labelKey: normalized.labelKey,
        value,
      });
    });
  }

  function snapshot() {
    return withGuard(() => {
      const countersSnapshot = Array.from(counters.values())
        .slice()
        .sort(compareEntries)
        .map((entry) => ({
          name: entry.name,
          labels: { ...entry.labels },
          value: entry.value,
        }));

      const gaugesSnapshot = Array.from(gauges.values())
        .slice()
        .sort(compareEntries)
        .map((entry) => ({
          name: entry.name,
          labels: { ...entry.labels },
          value: entry.value,
        }));

      const histogramsSnapshot = Array.from(histograms.values())
        .slice()
        .sort(compareEntries)
        .map((entry) => ({
          name: entry.name,
          labels: { ...entry.labels },
          count: entry.count,
          sum: entry.sum,
          buckets: HISTOGRAM_BUCKETS.map((bucket, index) => ({
            le: Number.isFinite(bucket) ? bucket : "+Inf",
            count: entry.bucketCounts[index],
          })),
        }));

      return {
        counters: countersSnapshot,
        histograms: histogramsSnapshot,
        gauges: gaugesSnapshot,
      };
    }) || {
      counters: [],
      histograms: [],
      gauges: [],
    };
  }

  function reset() {
    return withGuard(() => {
      counters.clear();
      gauges.clear();
      histograms.clear();
    });
  }

  return {
    increment,
    observe,
    gauge,
    snapshot,
    reset,
  };
}

module.exports = {
  createMetrics,
};
