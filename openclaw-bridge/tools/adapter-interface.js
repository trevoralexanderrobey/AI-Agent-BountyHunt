/**
 * ToolExecutionInput
 * @typedef {Object} ToolExecutionInput
 * @property {Object} params
 * @property {number} timeout
 * @property {string} requestId
 */

/**
 * ToolExecutionResult
 * @typedef {Object} ToolExecutionResult
 * @property {boolean} ok
 * @property {Object} [result]
 * @property {{ code: string, message: string }} [error]
 * @property {{
 *   executionTimeMs: number,
 *   outputBytes: number,
 *   requestId: string
 * }} metadata
 */

/**
 * ValidationResult
 * @typedef {Object} ValidationResult
 * @property {boolean} valid
 * @property {string[]} [errors]
 */

/**
 * Documentation interface for tool adapters.
 * Concrete adapters should implement this contract.
 */
class ToolAdapterInterface {
  constructor() {
    /** @type {string} */
    this.name = "";
    /** @type {string} */
    this.slug = "";
    /** @type {string} */
    this.description = "";
  }

  /**
   * @param {ToolExecutionInput} _input
   * @returns {Promise<ToolExecutionResult>}
   */
  async execute(_input) {
    throw new Error("Not implemented");
  }

  /**
   * @param {Object} _params
   * @returns {Promise<ValidationResult>}
   */
  async validateInput(_params) {
    throw new Error("Not implemented");
  }

  /**
   * @param {string|Object} _rawOutput
   * @returns {Promise<Object>}
   */
  async normalizeOutput(_rawOutput) {
    throw new Error("Not implemented");
  }

  /**
   * @returns {{ timeoutMs: number, memoryMb: number, maxOutputBytes: number }}
   */
  getResourceLimits() {
    throw new Error("Not implemented");
  }
}

module.exports = {
  ToolAdapterInterface,
};
