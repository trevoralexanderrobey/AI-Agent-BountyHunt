function sanitizeMetricName(name) {
  return String(name || "")
    .trim()
    .replace(/[^a-zA-Z0-9_]/g, "_")
    .replace(/_+/g, "_")
    .replace(/^_+/, "")
    .toLowerCase();
}

function sanitizeLabelKey(key) {
  const normalized = String(key || "")
    .trim()
    .replace(/[^a-zA-Z0-9_]/g, "_")
    .replace(/_+/g, "_")
    .replace(/^_+/, "")
    .toLowerCase();
  return normalized || "label";
}

function isSensitiveLabelKey(key) {
  return /(token|secret|password|authorization|auth|signature|container|networkaddress)/i.test(String(key || ""));
}

function escapeLabelValue(value) {
  return String(value || "")
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"')
    .replace(/\n/g, "\\n");
}

function buildLabelSet(labels) {
  if (!labels || typeof labels !== "object") {
    return "";
  }
  const parts = [];
  const keys = Object.keys(labels).sort();
  for (const key of keys) {
    if (isSensitiveLabelKey(key)) {
      continue;
    }
    const labelKey = sanitizeLabelKey(key);
    const labelValue = escapeLabelValue(labels[key]);
    parts.push(`${labelKey}="${labelValue}"`);
  }
  return parts.length > 0 ? `{${parts.join(",")}}` : "";
}

function createPrometheusExporter(metricsInstance) {
  function getSnapshot() {
    if (!metricsInstance) {
      return { counters: [], histograms: [], gauges: [] };
    }
    if (typeof metricsInstance.snapshot === "function") {
      return metricsInstance.snapshot();
    }
    if (typeof metricsInstance.getSnapshot === "function") {
      return metricsInstance.getSnapshot();
    }
    if (typeof metricsInstance === "function") {
      return metricsInstance();
    }
    return { counters: [], histograms: [], gauges: [] };
  }

  function render() {
    const snapshot = getSnapshot() || { counters: [], histograms: [], gauges: [] };
    const lines = [];
    const declared = new Set();

    const declareMetric = (metricName, type, helpText) => {
      const key = `${metricName}:${type}`;
      if (declared.has(key)) {
        return;
      }
      declared.add(key);
      lines.push(`# HELP ${metricName} ${helpText}`);
      lines.push(`# TYPE ${metricName} ${type}`);
    };

    const counters = Array.isArray(snapshot.counters) ? snapshot.counters : [];
    for (const entry of counters) {
      const metricName = sanitizeMetricName(entry.name);
      if (!metricName) {
        continue;
      }
      declareMetric(metricName, "counter", `${entry.name} counter`);
      const labels = buildLabelSet(entry.labels);
      lines.push(`${metricName}${labels} ${Number(entry.value) || 0}`);
    }

    const gauges = Array.isArray(snapshot.gauges) ? snapshot.gauges : [];
    for (const entry of gauges) {
      const metricName = sanitizeMetricName(entry.name);
      if (!metricName) {
        continue;
      }
      declareMetric(metricName, "gauge", `${entry.name} gauge`);
      const labels = buildLabelSet(entry.labels);
      lines.push(`${metricName}${labels} ${Number(entry.value) || 0}`);
    }

    const histograms = Array.isArray(snapshot.histograms) ? snapshot.histograms : [];
    for (const entry of histograms) {
      const metricName = sanitizeMetricName(entry.name);
      if (!metricName) {
        continue;
      }
      declareMetric(metricName, "histogram", `${entry.name} histogram`);

      const baseLabels = entry.labels && typeof entry.labels === "object" ? entry.labels : {};
      const buckets = Array.isArray(entry.buckets) ? entry.buckets : [];
      for (const bucket of buckets) {
        const labels = {
          ...baseLabels,
          le: bucket.le === "+Inf" ? "+Inf" : String(bucket.le),
        };
        lines.push(`${metricName}_bucket${buildLabelSet(labels)} ${Number(bucket.count) || 0}`);
      }

      lines.push(`${metricName}_sum${buildLabelSet(baseLabels)} ${Number(entry.sum) || 0}`);
      lines.push(`${metricName}_count${buildLabelSet(baseLabels)} ${Number(entry.count) || 0}`);
    }

    return `${lines.join("\n")}\n`;
  }

  return {
    render,
  };
}

module.exports = {
  createPrometheusExporter,
};
