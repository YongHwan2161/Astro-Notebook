const events = {};

export function on(eventName, callback) {
  if (!events[eventName]) {
    events[eventName] = [];
  }
  events[eventName].push(callback);
}

export function emit(eventName, data) {
  const eventCallbacks = events[eventName];
  if (eventCallbacks) {
    eventCallbacks.forEach(callback => callback(data));
  }
}