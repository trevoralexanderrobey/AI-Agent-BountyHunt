const IMAGE_POLICY_OPTION_KEYS = Object.freeze([
  "production",
  "allowedRegistries",
  "requireDigestPinning",
  "requireSignatureVerification",
  "signatureVerified",
]);

const DEFAULT_ALLOWED_REGISTRIES = Object.freeze(["docker.io", "ghcr.io", "quay.io"]);

function normalizeString(value) {
  return typeof value === "string" ? value.trim() : "";
}

function normalizeRegistryList(input) {
  if (!Array.isArray(input)) {
    return null;
  }
  const registries = [];
  for (const item of input) {
    if (typeof item !== "string" || item.trim().length === 0) {
      return null;
    }
    registries.push(item.trim());
  }
  return registries;
}

function parseImageMetadata(imageRef) {
  const image = normalizeString(imageRef);
  if (!image) {
    return {
      image,
      registry: "",
      tag: "",
      pinnedDigest: false,
      localOnly: true,
      implicitRegistry: true,
      hasCredentialPrefix: false,
    };
  }

  const credentialPrefixMatch = image.match(/^[^/]+:[^/@]+@/);
  const hasCredentialPrefix = Boolean(credentialPrefixMatch);
  const sanitizedRef = hasCredentialPrefix ? image.replace(/^[^/]+:[^/@]+@/, "") : image;

  const digestIndex = sanitizedRef.indexOf("@sha256:");
  const pinnedDigest = digestIndex !== -1;
  const withoutDigest = pinnedDigest ? sanitizedRef.slice(0, digestIndex) : sanitizedRef;
  const lastColon = withoutDigest.lastIndexOf(":");
  const lastSlash = withoutDigest.lastIndexOf("/");
  const tag = lastColon > lastSlash ? withoutDigest.slice(lastColon + 1) : "";
  const pathPart = lastColon > lastSlash ? withoutDigest.slice(0, lastColon) : withoutDigest;
  const firstSegment = pathPart.split("/")[0] || "";
  const explicitRegistry = firstSegment.includes(".") || firstSegment.includes(":") || firstSegment === "localhost";

  return {
    image: sanitizedRef,
    registry: explicitRegistry ? firstSegment : "",
    tag,
    pinnedDigest,
    localOnly: !explicitRegistry,
    implicitRegistry: !explicitRegistry,
    hasCredentialPrefix,
  };
}

function validateImageReference(imageRef, options = {}) {
  const errors = [];

  for (const key of Object.keys(options || {})) {
    if (!IMAGE_POLICY_OPTION_KEYS.includes(key)) {
      errors.push(`image policy options contain unknown field '${key}'`);
    }
  }

  const production = options.production === true;
  const requireDigestPinning = Object.prototype.hasOwnProperty.call(options, "requireDigestPinning")
    ? options.requireDigestPinning === true
    : true;
  const requireSignatureVerification = Object.prototype.hasOwnProperty.call(options, "requireSignatureVerification")
    ? options.requireSignatureVerification === true
    : true;
  const signatureProvided = Object.prototype.hasOwnProperty.call(options, "signatureVerified");
  const signatureVerified = signatureProvided ? options.signatureVerified === true : false;

  if (signatureProvided && typeof options.signatureVerified !== "boolean") {
    errors.push("signatureVerified must be a boolean when provided");
  }

  if (requireSignatureVerification && !signatureProvided) {
    errors.push("signatureVerified must be explicitly provided when signature verification is required");
  }

  const registries = options.allowedRegistries
    ? normalizeRegistryList(options.allowedRegistries)
    : DEFAULT_ALLOWED_REGISTRIES.slice();
  if (!registries) {
    errors.push("allowedRegistries must be an array of non-empty strings");
  }

  const meta = parseImageMetadata(imageRef);

  if (!meta.image) {
    errors.push("image reference is required");
  }

  if (meta.hasCredentialPrefix) {
    errors.push("image reference must not include embedded credentials");
  }

  if (meta.tag && meta.tag.toLowerCase() === "latest") {
    errors.push("image tag ':latest' is not allowed");
  }

  if (requireDigestPinning && !meta.pinnedDigest) {
    errors.push("image digest pinning is required");
  }

  if (production) {
    if (meta.localOnly) {
      errors.push("local-only image references are not allowed in production");
    }

    if (registries && meta.registry && !registries.includes(meta.registry)) {
      errors.push(`image registry '${meta.registry}' is not allowed`);
    }
  }

  if (requireSignatureVerification && !signatureVerified) {
    errors.push("image signature verification flag is required");
  }

  return {
    valid: errors.length === 0,
    errors,
    metadata: {
      image: meta.image,
      registry: meta.registry,
      tag: meta.tag,
      pinnedDigest: meta.pinnedDigest,
      localOnly: meta.localOnly,
      allowedRegistries: registries || [],
      signatureRequired: requireSignatureVerification,
      signatureVerified,
      signatureProvided,
    },
  };
}

module.exports = {
  DEFAULT_ALLOWED_REGISTRIES,
  IMAGE_POLICY_OPTION_KEYS,
  validateImageReference,
};
