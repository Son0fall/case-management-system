document.addEventListener('DOMContentLoaded', function () {
  // Sidebar toggle & footer year update (if applicable)
  const sidebar = document.getElementById('sidebar');
  const toggleBtn = document.getElementById('toggle-sidebar-btn');
  const footer = document.querySelector('.footer');
  if (toggleBtn && sidebar && footer) {
    toggleBtn.addEventListener('click', function () {
      sidebar.classList.toggle('open');
      footer.classList.toggle('open');
    });
  }
  const yearSpan = document.getElementById('current-year');
  if (yearSpan) {
    yearSpan.textContent = new Date().getFullYear();
  }

  // Dropdown functionality
  const dropdownContainer = document.getElementById('dropdown-container');
  if (dropdownContainer) {
    dropdownContainer.addEventListener('click', function () {
      dropdownContainer.classList.toggle('active');
    });
    document.addEventListener('click', function (event) {
      if (!dropdownContainer.contains(event.target)) {
        dropdownContainer.classList.remove('active');
      }
    });
  }

  // "Add User" modal event listeners
  const newUserButton = document.getElementById('new_user');
  const addUserModal = document.getElementById('addUserModal');
  if (newUserButton && addUserModal) {
    newUserButton.addEventListener('click', function () {
      addUserModal.style.display = 'block';
    });
    window.addEventListener('click', function (event) {
      if (event.target === addUserModal) {
        addUserModal.style.display = 'none';
      }
    });
  }

  // Add user form (AJAX submission)
  const addUserForm = document.getElementById('add-user-form');
  if (addUserForm) {
    addUserForm.addEventListener('submit', function (event) {
      event.preventDefault();
      let formData = new FormData(this);
      fetch('/add_user', { method: 'POST', body: formData })
        .then(response => response.json())
        .then(data => {
          alert(data.message);
          window.location.href = "/dashboard?view=view_list"; // Redirect after adding user
        });
    });
  }

  // Add case form (AJAX submission)
  const addCaseForm = document.getElementById('add-case-form');
  if (addCaseForm) {
    addCaseForm.addEventListener('submit', function (event) {
      event.preventDefault();
      let formData = new FormData(this);
      fetch('/add_case', { method: 'POST', body: formData })
        .then(response => response.json())
        .then(data => {
          alert(data.message);
          window.location.href = "/dashboard?view=view_cases"; // Redirect after adding case
        });
    });
  }
});

// Function to preview an image for any given input and preview element
function previewImage(inputId, previewId) {
  const input = document.getElementById(inputId);
  const preview = document.getElementById(previewId);
  if (input.files && input.files[0]) {
    const reader = new FileReader();
    reader.onload = function (e) {
      preview.src = e.target.result;
    };
    reader.readAsDataURL(input.files[0]);
  }
}

// Specific preview functions (they call previewImage with proper IDs)
function previewAvatar() {
  previewImage('avatar_path', 'avatar_preview');
}
function previewNewAvatar() {
  previewImage('new_avatar', 'new_avatar_preview');
}

// Closes the Add User modal.
function closeModal() {
  const modal = document.getElementById('addUserModal');
  if (modal) {
    modal.style.display = 'none';
  }
}

// Global flag to control auto-refresh while editing.
var isEditing = false;

// Function to populate the update form with the selected user's data.
function editUser(id, email, username, role, avatarPath) {
  // Set the editing flag so that auto-refresh is skipped while editing.
  isEditing = true;
  
  // Set the hidden field.
  document.getElementById('user_id').value = id;
  document.getElementById('email').value = email;
  document.getElementById('username').value = username;
  document.getElementById('role').value = role;

  // Update the avatar preview.
  var avatarPreview = document.getElementById('avatar_preview');
  if (avatarPath && avatarPath.trim() !== "") {
    avatarPreview.src = avatarPath;
    avatarPreview.style.display = "block";
  } else {
    avatarPreview.src = "#";
    avatarPreview.style.display = "none";
  }

  // Update the form action dynamically.
  document.getElementById('user-form').action = "/update_user/" + id;
}

// Simple function to reset the update form.
function resetForm() {
  isEditing = false;
  document.getElementById('user-form').reset();
  document.getElementById('avatar_preview').src = "#";
}

// Preview avatar for update form.
function previewAvatar() {
  var input = document.getElementById('avatar_path');
  var preview = document.getElementById('avatar_preview');
  if (input.files && input.files[0]) {
    var reader = new FileReader();
    reader.onload = function(e) {
      preview.src = e.target.result;
      preview.style.display = "block";
    }
    reader.readAsDataURL(input.files[0]);
  }
}

// Preview avatar for add user modal.
function previewNewAvatar() {
  var input = document.getElementById('new_avatar');
  var preview = document.getElementById('new_avatar_preview');
  if (input.files && input.files[0]) {
    var reader = new FileReader();
    reader.onload = function(e) {
      preview.src = e.target.result;
      preview.style.display = "block";
    }
    reader.readAsDataURL(input.files[0]);
  }
}

// Modal open/close functions.
document.getElementById("new_user").addEventListener("click", function () {
  document.getElementById("addUserModal").style.display = "block";
});

function closeModal() {
  document.getElementById("addUserModal").style.display = "none";
}

// -------------------- Auto-Refresh Code --------------------

// This function refreshes the dashboard's main content without full page reload.
function refreshDashboard() {
  if (isEditing) {
    // Skip the refresh if the update form is being edited.
    console.log("Auto-refresh skipped: form is being edited.");
    return;
  }
  
  let currentUrl = new URL(window.location.href);
  let currentView = currentUrl.searchParams.get("view") || "cards";
  
  fetch("{{ url_for('dashboard') }}?view=" + currentView)
    .then(response => response.text())
    .then(html => {
      const tempDiv = document.createElement("div");
      tempDiv.innerHTML = html;
      const newContent = tempDiv.querySelector(".main-content");
      if (newContent) {
        document.querySelector(".main-content").innerHTML = newContent.innerHTML;
      }
    })
    .catch(error => console.error("Error refreshing dashboard:", error));
}

// Set auto-refresh to trigger every 30 seconds (30000 milliseconds)
setInterval(refreshDashboard, 30000);
