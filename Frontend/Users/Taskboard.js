function EnableDragAndDrop() {
    // Enable dropping on each column
    ['todo-column', 'in-progress-column', 'done-column'].forEach(columnId => {
        const column = document.getElementById(columnId);
        column.ondragover = (event) => {
            event.preventDefault(); // Allow drop
        };
        column.ondrop = (event) => {
            event.preventDefault();
            const taskId = event.dataTransfer.getData("text/plain");
            const taskCard = document.getElementById(`task-${taskId}`);
            column.appendChild(taskCard); // Move card to new column
        
            // Get new status based on column
            let newStatus = '';
            if (column.id === 'todo-column') newStatus = 'To-Do';
            else if (column.id === 'in-progress-column') newStatus = 'In Progress';
            else if (column.id === 'done-column') newStatus = 'Done';
        
            // Update backend
            const token = sessionStorage.getItem('token');
            fetch(`http://localhost:3000/update-task-status/${taskId}`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer ' + token
                },
                body: JSON.stringify({ status: newStatus })
            })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    console.log(`Task ${taskId} status updated to ${newStatus}`);
                } else {
                    console.error('Failed to update status');
                }
            })
            .catch(err => {
                console.error('Error updating task status:', err);
            });
        };
        
    });
}

function LoadTasksToBoard() {
    const token = sessionStorage.getItem('token');

    fetch('http://localhost:3000/tasks-assigned', {
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
            taskCard.setAttribute('draggable', 'true');
            taskCard.setAttribute('id', `task-${task.id}`);
            taskCard.ondragstart = (event) => {
                event.dataTransfer.setData("text/plain", task.id);
            };

            taskCard.style = 'background: white; padding: 10px; margin: 10px 0; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); text-align: left;';
            taskCard.innerHTML = `
                <strong>${task.title}</strong><br>
                <small>Due: ${new Date(task.due_date).toLocaleDateString()}</small><br>
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

        EnableDragAndDrop(); // Initialize drag-and-drop after tasks are loaded
    })
    .catch(err => {
        console.error('Failed to load tasks:', err);
    });
}

// Call this function when the page loads
window.onload = LoadTasksToBoard;
