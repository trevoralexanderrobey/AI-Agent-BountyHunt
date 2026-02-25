class RequestQueue {
  constructor(maxLength = 100) {
    this.maxLength = Number.isFinite(maxLength) && maxLength > 0 ? Math.floor(maxLength) : 100;
    this._store = new Map();
    this._head = 0;
    this._tail = 0;
    this._size = 0;
  }

  get length() {
    return this._size;
  }

  get empty() {
    return this._size === 0;
  }

  enqueue(item) {
    if (this._size >= this.maxLength) {
      return false;
    }
    this._store.set(this._tail, item);
    this._tail += 1;
    this._size += 1;
    return true;
  }

  peek() {
    if (this._size === 0) {
      return null;
    }
    return this._store.get(this._head) || null;
  }

  dequeue() {
    if (this._size === 0) {
      return null;
    }
    const value = this._store.get(this._head) || null;
    this._store.delete(this._head);
    this._head += 1;
    this._size -= 1;

    if (this._size === 0) {
      this._head = 0;
      this._tail = 0;
    }
    return value;
  }

  clear() {
    this._store.clear();
    this._head = 0;
    this._tail = 0;
    this._size = 0;
  }
}

module.exports = {
  RequestQueue,
};
