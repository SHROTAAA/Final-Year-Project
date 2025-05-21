async function toggleNotificationBox() {
  const box = document.getElementById('notification-box');
  const isOpening = box.style.display !== 'block';
  box.style.display = isOpening ? 'block' : 'none';

  if (isOpening) {
    unreadCount = 0;
    updateBadge(0);

    const userId = sessionStorage.getItem('userId');

    const res = await fetch(`http://localhost:3000/api/notifications/mark-read`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userId }),
    });
    const data = await res.json();
    console.log('Marked as read:', data);
  }
}

window.addEventListener('click', function (e) {
  const icon = document.getElementById('notification-icon');
  const box = document.getElementById('notification-box');
  if (!icon.contains(e.target) && !box.contains(e.target)) {
    box.style.display = 'none';
  }
});

const userId = sessionStorage.getItem('userId'); 
const wss = new WebSocket('ws://localhost:3000');

window.addEventListener('DOMContentLoaded', async () => {
  if (!userId) return;

  // Load unread count
  try {
    const res = await fetch(`http://localhost:3000/api/unread-count?userId=${userId}`);
    const data = await res.json();
    unreadCount = data.count || 0;
    updateBadge(unreadCount);
  } catch (err) {
    console.error('❌ Failed to load unread count:', err);
  }

  // Load notifications
  try {
    const response = await fetch(`http://localhost:3000/api/notifications?userId=${userId}`);
    const notifications = await response.json();
    notifications.reverse().forEach(n => {
      showNotification(n.message, n.timestamp, n.id);
    });
  } catch (err) {
    console.error('❌ Failed to load notifications from DB:', err);
  }
});


wss.onopen = () => {
  console.log('WebSocket connection established');
  wss.send(JSON.stringify({ type: 'REGISTER_USER', userId }));
};

wss.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('Received WS message:', data);

  const currentUserId = sessionStorage.getItem('userId');
  let message;
  const timestamp = data.timestamp || new Date().toISOString(); // fallback

  if (data.type === 'TASK_STATUS_UPDATED') {
    message = data.message ?? `${data.userName} updated task "${data.taskTitle}" to "${data.status}" in project "${data.projectName}"`;
    showNotification(message, timestamp);
    unreadCount++;
    updateBadge(unreadCount);
    playNotificationSound();

  } else if (data.type === 'TASK_ASSIGNED') {
    // Only show if this user is the assigned user
    message = data.message; // assume backend sends proper message
    showNotification(message, timestamp);
    unreadCount++;
    updateBadge(unreadCount);
    playNotificationSound();
  }
};


function updateBadge(count) {
  const badge = document.getElementById('notification-badge');
  if (!badge) return;
  if (count > 0) {
    badge.textContent = count;
    badge.style.display = 'inline-block';
  } else {
    badge.style.display = 'none';
  }
}

function playNotificationSound() {
  const sound = document.getElementById('notification-sound');
  if (sound) {
    sound.currentTime = 0;
    sound.play().catch(e => console.warn('Notification sound play failed:', e));
  }
}

function showNotification(message, timestamp = null, id) {
  const container = document.getElementById('notification-content');

  // Remove placeholders
  const placeholderIcon = container.querySelector('.big-icon');
  const placeholderText = container.querySelector('.no-notify-text');
  if (placeholderIcon) placeholderIcon.remove();
  if (placeholderText) placeholderText.remove();

  // Format time
  let timeDisplay = '';
  if (timestamp) {
    const date = new Date(timestamp);
    const now = new Date();

    const isToday = date.toDateString() === now.toDateString();
    const yesterday = new Date(); yesterday.setDate(now.getDate() - 1);
    const isYesterday = date.toDateString() === yesterday.toDateString();
    const timeString = date.toLocaleString('en-US', {
      hour: 'numeric',
      minute: '2-digit',
      hour12: true,
    });

    if (isToday) {
      timeDisplay = `Today, ${timeString}`;
    } else if (isYesterday) {
      timeDisplay = `Yesterday, ${timeString}`;
    } else {
      const dayString = date.toLocaleString('en-US', { weekday: 'short' });
      timeDisplay = `${dayString}, ${timeString}`;
    }
  }

  // Notification container
  const notification = document.createElement('div');
  notification.className = 'notify-item';
  notification.style.display = 'flex';
  notification.style.justifyContent = 'space-between';
  notification.style.alignItems = 'center';
  notification.style.padding = '8px 10px';
  notification.style.borderBottom = '1px solid #eee';
  notification.style.backgroundColor = '#f9f9f9';
  notification.style.borderRadius = '5px';
  notification.style.marginBottom = '8px';

  const closeBtn = document.createElement('span');
  closeBtn.textContent = '✖';
  closeBtn.className = 'close-btn';
  closeBtn.style.cursor = 'pointer';
  closeBtn.style.color = '#888';
  closeBtn.style.fontSize = '14px';

  closeBtn.addEventListener('click', () => {
    container.removeChild(notification);

    // Placeholder if empty
    if (container.children.length === 0) {
      const icon = document.createElement('i');
      icon.className = 'fas fa-bell-slash big-icon';
      const text = document.createElement('p');
      text.className = 'no-notify-text';
      text.textContent = 'No new notifications';
      container.appendChild(icon);
      container.appendChild(text);
    }

    // Delete from DB
    if (id) {
      fetch(`http://localhost:3000/api/notifications/${id}`, {
        method: 'DELETE',
      })
      .then(res => res.json())
      .then(data => {
        if (!data.success) console.error('❌ Delete failed:', data.error);
      })
      .catch(err => console.error('❌ Error deleting:', err));
    }
  });

  const contentWrapper = document.createElement('div');
  contentWrapper.innerHTML = `
    <div>${message}</div>
    ${timeDisplay ? `<div class="notify-time">${timeDisplay}</div>` : ''}
  `;

  notification.appendChild(contentWrapper);
  notification.appendChild(closeBtn);
  container.prepend(notification);
}

