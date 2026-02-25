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

  toArray() {
    if (this._size === 0) {
      return [];
    }
    const items = [];
    for (let index = this._head; index < this._tail; index += 1) {
      if (!this._store.has(index)) {
        continue;
      }
      items.push(this._store.get(index));
    }
    return items;
  }

  fromArray(items) {
    if (!Array.isArray(items)) {
      this.clear();
      return 0;
    }

    this.clear();
    let loaded = 0;
    for (const item of items) {
      if (loaded >= this.maxLength) {
        break;
      }
      this._store.set(this._tail, item);
      this._tail += 1;
      this._size += 1;
      loaded += 1;
    }
    return loaded;
  }
}

module.exports = {
  RequestQueue,
};
