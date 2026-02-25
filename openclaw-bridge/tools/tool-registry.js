const SLUG_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

function isValidAdapter(adapter) {
  if (!adapter || typeof adapter !== "object") {
    return false;
  }

  const requiredMethods = ["execute", "validateInput", "normalizeOutput", "getResourceLimits"];
  for (const method of requiredMethods) {
    if (typeof adapter[method] !== "function") {
      return false;
    }
  }

  if (typeof adapter.name !== "string" || adapter.name.trim().length === 0) {
    return false;
  }
  if (typeof adapter.slug !== "string" || adapter.slug.trim().length === 0) {
    return false;
  }
  if (typeof adapter.description !== "string") {
    return false;
  }

  return true;
}

function normalizeSlug(rawSlug) {
  return typeof rawSlug === "string" ? rawSlug.trim().toLowerCase() : "";
}

function createToolRegistry(config = {}) {
  const strict = config.strict !== false;
  const entries = new Map();
  let sealed = false;

  function ensureWritable() {
    if (sealed) {
      throw new Error("Tool registry is sealed");
    }
  }

  function register(rawSlug, adapter, options = {}) {
    ensureWritable();
    const slug = normalizeSlug(rawSlug);
    if (!slug || !SLUG_PATTERN.test(slug)) {
      throw new Error("Invalid tool slug");
    }
    if (entries.has(slug)) {
      throw new Error(`Duplicate tool slug '${slug}'`);
    }
    if (!isValidAdapter(adapter)) {
      throw new Error(`Adapter for '${slug}' does not implement ToolAdapter interface`);
    }
    if (normalizeSlug(adapter.slug) !== slug) {
      throw new Error(`Adapter slug '${adapter.slug}' does not match registry slug '${slug}'`);
    }

    entries.set(slug, {
      adapter,
      enabled: options.enabled !== false,
    });
    return adapter;
  }

  function has(rawSlug) {
    const slug = normalizeSlug(rawSlug);
    return entries.has(slug);
  }

  function get(rawSlug) {
    const slug = normalizeSlug(rawSlug);
    const entry = entries.get(slug);
    if (!entry || entry.enabled !== true) {
      return null;
    }
    return entry.adapter;
  }

  function list() {
    return Array.from(entries.entries())
      .sort((a, b) => a[0].localeCompare(b[0]))
      .map(([slug, entry]) => ({
        slug,
        name: entry.adapter.name,
        enabled: entry.enabled === true,
      }));
  }

  function seal() {
    sealed = true;
  }

  if (config && Array.isArray(config.initial)) {
    for (const item of config.initial) {
      if (!item || typeof item !== "object") {
        continue;
      }
      register(item.slug, item.adapter, { enabled: item.enabled });
    }
  }

  if (strict) {
    seal();
  }

  return {
    strict,
    register,
    has,
    get,
    list,
    seal,
  };
}

module.exports = {
  createToolRegistry,
  isValidAdapter,
};
