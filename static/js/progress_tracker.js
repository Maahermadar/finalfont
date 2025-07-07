// Progress Details Modal
const progressDetailsModal = document.getElementById('progress-details-modal');
const progressModalTitle = document.getElementById('progress-modal-title');
const progressModalBody = document.getElementById('progress-modal-body');
const progressCloseButton = progressDetailsModal.querySelector('.close-button');

// Handle View More clicks
document.querySelectorAll('.view-more-btn').forEach(btn => {
    btn.addEventListener('click', async function(e) {
        e.preventDefault();
        const subject = this.dataset.subject;
        
        progressModalTitle.textContent = `Detailed Progress - ${subject}`;
        progressModalBody.innerHTML = '<div class="loader"></div>';
        progressDetailsModal.style.display = 'block';

        try {
            const response = await fetch(`/api/subject_details?subject=${encodeURIComponent(subject)}`);
            const data = await response.json();

            if (response.ok) {
                let html = `
                    <div class="progress-section">
                        <h3>Approved Videos Progress</h3>
                        <div class="progress-bar-container">
                            <div class="progress-bar ${data.color_class}" 
                                 data-progress="${data.progress}"
                                 style="--progress-width: ${data.progress}%">
                            </div>
                        </div>
                        <div class="progress-stats">
                            ${data.approved} of ${data.total_episodes} videos approved
                        </div>
                    </div>
                    
                    <div class="progress-section">
                        <h3>Shooting Progress</h3>
                        <div class="progress-bar-container">
                            <div class="progress-bar ${data.shooting_color_class}" 
                                 data-progress="${data.shooting_progress}"
                                 style="--progress-width: ${data.shooting_progress}%">
                            </div>
                        </div>
                        <div class="progress-stats">
                            ${data.shooting_total} of ${data.total_episodes} videos in production
                        </div>
                    </div>
                `;
                progressModalBody.innerHTML = html;
            } else {
                progressModalBody.innerHTML = `<p>${data.error || 'Failed to load progress details.'}</p>`;
            }
        } catch (error) {
            progressModalBody.innerHTML = `<p>An error occurred: ${error.message}</p>`;
        }
    });
});

// Close progress details modal
progressCloseButton.addEventListener('click', function() {
    progressDetailsModal.style.display = 'none';
});

window.addEventListener('click', function(event) {
    if (event.target == progressDetailsModal) {
        progressDetailsModal.style.display = 'none';
    }
}); 