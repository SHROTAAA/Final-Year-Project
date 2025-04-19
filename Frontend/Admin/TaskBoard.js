function loadTasksToBoard() {
    const token = sessionStorage.getItem('token');

    fetch('http://localhost:3000/tasks-assigned-by-admin', {
        method: 'GET',
        headers: {
            'Authorization': 'Bearer ' + token
        }
    })
    .then(response => response.json())
    .then(tasks => {
        tasks.forEach(task => {
            const taskCard = document.createElement('div');
            taskCard.className = 'task-card';
            taskCard.style = 'background: white; padding: 10px; margin: 10px 0; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); text-align: left;';
            taskCard.innerHTML = `
                <strong>${task.title}</strong><br>
                <small>Due: ${new Date(task.due_date).toLocaleDateString()}</small><br>
                <small>Assigned to: ${task.assigned_to_name}</small><br>
                <small>Project: ${task.project_name}</small>
            `;

            if (task.status === 'To-Do') {
                document.getElementById('todo-column').appendChild(taskCard);
            } else if (task.status === 'In Progress') {
                document.getElementById('in-progress-column').appendChild(taskCard);
            } else if (task.status === 'Done') {
                document.getElementById('done-column').appendChild(taskCard);
            }
        });
    })
    .catch(err => {
        console.error('Failed to load tasks:', err);
    });
}
