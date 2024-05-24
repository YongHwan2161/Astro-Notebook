import React, { useState, useEffect } from 'react';

const App = () => {
  const [posts, setPosts] = useState([]);
  const [messages, setMessages] = useState([]);
  const [postContent, setPostContent] = useState('');
  const [messageContent, setMessageContent] = useState('');

  useEffect(() => {
    fetch('/posts')
      .then(res => res.json())
      .then(data => setPosts(data));

    fetch('/messages')
      .then(res => res.json())
      .then(data => setMessages(data));
  }, []);

  const handlePostSubmit = (e) => {
    e.preventDefault();
    fetch('/posts', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ content: postContent }),
    })
      .then(res => res.json())
      .then(data => setPosts([...posts, data]));
    setPostContent('');
  };

  const handleMessageSubmit = (e) => {
    e.preventDefault();
    fetch('/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ content: messageContent }),
    })
      .then(res => res.json())
      .then(data => setMessages([...messages, data]));
    setMessageContent('');
  };

  return (
    <div>
      <h1>Simple Blog and Chat</h1>
      <div>
        <h2>Blog</h2>
        <form onSubmit={handlePostSubmit}>
          <input
            type="text"
            value={postContent}
            onChange={(e) => setPostContent(e.target.value)}
            placeholder="Write a post"
            required
          />
          <button type="submit">Post</button>
        </form>
        <ul>
          {posts.map((post, index) => (
            <li key={index}>{post.content}</li>
          ))}
        </ul>
      </div>
      <div>
        <h2>Chat</h2>
        <form onSubmit={handleMessageSubmit}>
          <input
            type="text"
            value={messageContent}
            onChange={(e) => setMessageContent(e.target.value)}
            placeholder="Write a message"
            required
          />
          <button type="submit">Send</button>
        </form>
        <ul>
          {messages.map((message, index) => (
            <li key={index}>{message.content}</li>
          ))}
        </ul>
      </div>
    </div>
  );
};

export default App;
