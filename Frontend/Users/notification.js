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