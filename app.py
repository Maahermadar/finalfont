from flask import Flask, render_template, request, redirect, url_for, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
import os
from datetime import datetime

from flask import send_file
import pandas as pd
import io



# ... (same imports as before)

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sec_videos.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'

db = SQLAlchemy(app)

class Video(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(100), nullable=False)
    chapter = db.Column(db.String(200), nullable=False)
    episode = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(50), nullable=False, default="Under Review")
    date = db.Column(db.String(20), nullable=False)
    file_path = db.Column(db.String(200), nullable=True)

with app.app_context():
    db.create_all()

@app.template_filter('basename')
def basename_filter(path):
    return os.path.basename(path)



@app.route('/review', methods=['GET'])
def review():
    subject_filter = request.args.get('subject', 'All')
    status_filter = request.args.get('status', 'All')

    # Start with all videos
    query = Video.query

    # Apply filters only if they're not "All"
    if subject_filter and subject_filter != 'All':
        query = query.filter_by(subject=subject_filter)

    if status_filter and status_filter != 'All':
        query = query.filter_by(status=status_filter)

    videos = query.all()

    # Get all unique subjects and statuses for the dropdowns
    subjects = [row[0] for row in db.session.query(Video.subject).distinct()]
    statuses = [row[0] for row in db.session.query(Video.status).distinct()]

    return render_template(
        'review.html',
        videos=videos,
        subjects=subjects,
        statuses=statuses
    )



@app.route('/approval')
def approval():
    subject_filter = request.args.get('subject')

    if subject_filter:
        videos = Video.query.filter_by(status='Approved', subject=subject_filter).all()
    else:
        videos = Video.query.filter_by(status='Approved').all()

    subjects = db.session.query(Video.subject).distinct().all()

    # Stats (optional)
    subject_stats = {}
    for subject in subjects:
        subject_name = subject[0]
        approved_count = Video.query.filter_by(subject=subject_name, status='Approved').count()
        under_review_count = Video.query.filter_by(subject=subject_name, status='Under Review').count()
        pending_count = Video.query.filter_by(subject=subject_name, status='Pending').count()
        subject_stats[subject_name] = {
            'approved': approved_count,
            'under_review': under_review_count,
            'pending': pending_count
        }



    return render_template('approval.html', videos=videos, subjects=subjects, subject_stats=subject_stats)





@app.route('/add_video', methods=['POST'])
def add_video():
    subject = request.form['subject']
    chapter = request.form['chapter']
    episode = request.form['episode']
    date = request.form['date']
    status = request.form['status']

    file_path = None
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    if status == "Pending" and 'file_upload' in request.files:
        uploaded_file = request.files['file_upload']
        if uploaded_file and uploaded_file.filename:
            filename = secure_filename(uploaded_file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            uploaded_file.save(file_path)

    new_video = Video(
        subject=subject,
        chapter=chapter,
        episode=episode,
        status=status,
        date=date,
        file_path=file_path
    )

    db.session.add(new_video)
    db.session.commit()
    return redirect(url_for('review'))


@app.route('/edit_video/<int:video_id>', methods=['GET', 'POST'])
def edit_video(video_id):
    video = Video.query.get_or_404(video_id)  # Fetch the video from the database by ID
    
    if request.method == 'POST':
        # Get the new status from the form
        new_status = request.form['status']

        # Update the video details if form is submitted
        video.subject = request.form['subject']
        video.chapter = request.form['chapter']
        video.episode = request.form['episode']
        video.date = request.form['date']
        
        # If a new file is uploaded, update the file path
        if 'file_upload' in request.files:
            file = request.files['file_upload']
            if file:
                # Save the file and update the file path in the database
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                video.file_path = filename

        # Check if the status has changed from "Approved" to "Under Review" or "Pending"
        if video.status == 'Approved' and new_status in ['Under Review', 'Pending']:
            video.status = new_status  # Update the status to the new one
        elif video.status != new_status:
            video.status = new_status  # Update the status if changed

        db.session.commit()  # Commit all the changes to the database
        return redirect(url_for('review'))  # Redirect back to the review page

    return render_template('edit_video.html', video=video)



@app.route('/delete/<int:video_id>')
def delete_video(video_id):
    video = Video.query.get_or_404(video_id)
    if video.file_path and os.path.exists(video.file_path):
        os.remove(video.file_path)
    db.session.delete(video)
    db.session.commit()
    return redirect(url_for('review'))

@app.route('/uploads/<filename>')
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)







# Function to parse date in multiple formats
def parse_date(date_str):
    try:
        # Try parsing MM/DD/YYYY format
        return datetime.strptime(date_str.strip(), '%m/%d/%Y') if date_str else None
    except ValueError:
        try:
            # Try parsing YYYY-MM-DD format
            return datetime.strptime(date_str.strip(), '%Y-%m-%d') if date_str else None
        except ValueError:
            return None

@app.route('/download/<subject>')
def download_subject(subject):
    # Query approved videos for the given subject
    videos = Video.query.filter_by(subject=subject, status='Approved').all()

    # Prepare data for DataFrame
    data = []
    for v in videos:
        # Parse and format the date
        parsed_date = parse_date(v.date)
        formatted_date = parsed_date.strftime('%Y-%m-%d') if parsed_date else ''  # Format as 'YYYY-MM-DD'

        # Add the video data to the list
        data.append({
            'Subject': v.subject,
            'Chapter': v.chapter,
            'Episode': v.episode,
            'Date': formatted_date
        })

    # Create a DataFrame from the list of video data
    df = pd.DataFrame(data)

    # Create an in-memory output file
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, index=False, sheet_name='Approved Videos')

    # Move the pointer to the beginning of the file before sending it
    output.seek(0)

    # Send the file to the client
    return send_file(output, as_attachment=True, download_name=f'{subject}_approved.xlsx', mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')







if __name__ == '__main__':
    app.run(debug=True)


