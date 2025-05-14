function toggleNotificationBox() {
  const box = document.getElementById('notification-box');
  box.style.display = (box.style.display === 'block') ? 'none' : 'block';
}

window.addEventListener('click', function (e) {
  const icon = document.getElementById('notification-icon');
  const box = document.getElementById('notification-box');
  if (!icon.contains(e.target) && !box.contains(e.target)) {
    box.style.display = 'none';
  }
});

const adminId = sessionStorage.getItem('adminId'); // Adjust as needed
const wss = new WebSocket('ws://localhost:3000');

window.addEventListener('DOMContentLoaded', async () => {
  const adminId = sessionStorage.getItem('adminId');
  if (!adminId) return;

  try {
    const response = await fetch(`http://localhost:3000/api/notifications?adminId=${adminId}`);
    const notifications = await response.json();

    notifications.forEach(n => {
        showNotification(n.message, n.timestamp, n.id);
    });

  } catch (err) {
    console.error('❌ Failed to load notifications from DB:', err);
  }
});


wss.onopen = () => {
  console.log('✅ WebSocket connection established');
  wss.send(JSON.stringify({ type: 'REGISTER_ADMIN', adminId }));
};

wss.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('📩 Received WS message:', data);

  if (data.type === 'USER_JOINED') {
    const message = data.message ?? `${data.user?.fullname} joined the project ${data.projectName}`;
    const timestamp = data.timestamp;  // Receive timestamp
    showNotification(message, timestamp);  // Pass timestamp to showNotification
  }
};

function showNotification(message, timestamp = null, id) {
  const container = document.getElementById('notification-content');

  // Remove placeholders
  const placeholderIcon = container.querySelector('.big-icon');
  const placeholderText = container.querySelector('.no-notify-text');
  if (placeholderIcon) placeholderIcon.remove();
  if (placeholderText) placeholderText.remove();

  // Format time
  // Format time with Today/Yesterday/day logic
let timeDisplay = '';
if (timestamp) {
  const date = new Date(timestamp);
  const now = new Date();

  const isToday = date.toDateString() === now.toDateString();

  const yesterday = new Date();
  yesterday.setDate(now.getDate() - 1);
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


  // Create notification item container
  const notification = document.createElement('div');
  notification.className = 'notify-item';
  notification.style.display = 'flex';
  notification.style.justifyContent = 'space-between'; // Add this to push the X button to the right
  notification.style.alignItems = 'center';
  notification.style.padding = '8px 10px';
  notification.style.borderBottom = '1px solid #eee';
  notification.style.backgroundColor = '#f9f9f9';
  notification.style.borderRadius = '5px';
  notification.style.marginBottom = '8px';

  // Create close button and move it to the right
  const closeBtn = document.createElement('span');
  closeBtn.textContent = '✖';
  closeBtn.className = 'close-btn';
  closeBtn.style.cursor = 'pointer';
  closeBtn.style.color = '#888';
  closeBtn.style.fontSize = '14px';

  // Handle click to remove notification from UI and DB
  closeBtn.addEventListener('click', () => {
  container.removeChild(notification);

  // Check if container has any more notifications
  if (container.children.length === 0) {
    // Add placeholder icon and text back
    const icon = document.createElement('i');
    icon.className = 'fas fa-bell-slash big-icon';

    const text = document.createElement('p');
    text.className = 'no-notify-text';
    text.textContent = 'No new notifications';

    container.appendChild(icon);
    container.appendChild(text);
  }

  // Send DELETE request to remove from DB
  fetch(`http://localhost:3000/api/notifications/${id}`, {
    method: 'DELETE',
  })
    .then((response) => response.json())
    .then((data) => {
      if (data.success) {
        console.log('✅ Notification deleted from DB');
      } else {
        console.error('❌ Failed to delete notification from DB', data.error);
      }
    })
    .catch((err) => console.error('❌ Error deleting from DB:', err));
});


  // Notification message + time wrapper
  const contentWrapper = document.createElement('div');
  contentWrapper.innerHTML = `
    <div>${message}</div>
    ${timeDisplay ? `<div class="notify-time">${timeDisplay}</div>` : ''}
  `;

  // Add close button on the right side of the notification
  notification.appendChild(contentWrapper);
  notification.appendChild(closeBtn);

  container.prepend(notification);
}
