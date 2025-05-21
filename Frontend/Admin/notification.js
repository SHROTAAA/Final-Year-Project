async function toggleNotificationBox() {
  const box = document.getElementById('notification-box');
  const isOpening = box.style.display !== 'block';
  box.style.display = isOpening ? 'block' : 'none';

  if (isOpening) {
    unreadCount = 0;
    updateBadge(0);

    const adminId = sessionStorage.getItem('adminId');

    const res = await fetch(`http://localhost:3000/api/notifications/mark-read`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ adminId }),
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

const adminId = sessionStorage.getItem('adminId');
const wss = new WebSocket('ws://localhost:3000');
function formatDateTime(isoString) {
  const date = new Date(isoString);
  const options = {
    hour: '2-digit',
    minute: '2-digit',
    hour12: true,
    day: '2-digit',
    month: 'short',
    year: 'numeric'
  };
  return date.toLocaleString('en-US', options);
}

let unreadCount = 0;

window.addEventListener('DOMContentLoaded', async () => {
  if (!adminId) return;

  // Load unread count
  try {
    const res = await fetch(`http://localhost:3000/api/unread-count?adminId=${adminId}`);
    const data = await res.json();
    unreadCount = data.count || 0;
    updateBadge(unreadCount);
  } catch (err) {
    console.error('❌ Failed to load unread count:', err);
  }

  // Load notifications
  try {
    const response = await fetch(`http://localhost:3000/api/notifications?adminId=${adminId}`);
    const notifications = await response.json();
    [...notifications].reverse().forEach(n => {
      showNotification(n.message, n.timestamp, n.id);
    });

  } catch (err) {
    console.error('❌ Failed to load notifications from DB:', err);
  }
});

wss.onopen = () => {
  console.log('WebSocket connection established');
  wss.send(JSON.stringify({ type: 'REGISTER_ADMIN', adminId }));
};

wss.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('📩 Received WS message:', data);

  if (['USER_JOINED', 'TASK_STATUS_UPDATED', 'TASK_SUBMISSION'].includes(data.type)) {
    const message = data.message;
    const timestamp = data.timestamp || new Date().toISOString();
    console.log('⏱️ Used timestamp:', timestamp);

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

  const localTimeZone = Intl.DateTimeFormat().resolvedOptions().timeZone;
  const date = new Date(timestamp);
  const now = new Date();

  // Convert to local time for display
  const localTimeString = date.toLocaleTimeString('en-US', {
    hour: 'numeric',
    minute: '2-digit',
    hour12: true,
    timeZone: localTimeZone, // ⬅️ Use browser’s timezone
  });

  const localDateString = date.toLocaleDateString('en-US', {
    timeZone: localTimeZone,
  });
  const nowDateString = now.toLocaleDateString('en-US', {
    timeZone: localTimeZone,
  });

  // Check today/yesterday
  const isToday = localDateString === nowDateString;

  const yesterday = new Date();
  yesterday.setDate(now.getDate() - 1);
  const yesterdayDateString = yesterday.toLocaleDateString('en-US', {
    timeZone: localTimeZone,
  });
  const isYesterday = localDateString === yesterdayDateString;

  // Build final display
  if (isToday) {
    timeDisplay = `Today, ${localTimeString}`;
  } else if (isYesterday) {
    timeDisplay = `Yesterday, ${localTimeString}`;
  } else {
    const weekday = date.toLocaleDateString('en-US', {
      weekday: 'short',
      timeZone: localTimeZone,
    });
    timeDisplay = `${weekday}, ${localTimeString}`;
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
