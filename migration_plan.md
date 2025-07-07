# Grade Support Migration Plan

## Overview
Add grade support to existing single-grade (Grade 4) system to support Grades 1-4 with different subjects per grade.

## Migration Strategy: Add Grade Column

### Phase 1: Database Schema Updates

#### 1. Add Grade Column to Core Tables
```sql
-- Add grade column to main tables
ALTER TABLE video ADD COLUMN grade INTEGER NOT NULL DEFAULT 4;
ALTER TABLE raw_video ADD COLUMN grade INTEGER NOT NULL DEFAULT 4;
ALTER TABLE editor_handoff ADD COLUMN grade INTEGER NOT NULL DEFAULT 4;
ALTER TABLE review_comments_log ADD COLUMN grade INTEGER NOT NULL DEFAULT 4;
ALTER TABLE source_material ADD COLUMN grade INTEGER NOT NULL DEFAULT 4;
ALTER TABLE quick_review_item ADD COLUMN grade INTEGER NOT NULL DEFAULT 4;

-- Add grade column to Subject table
ALTER TABLE subject ADD COLUMN grade INTEGER NOT NULL DEFAULT 4;

-- Create composite indexes for better performance
CREATE INDEX idx_video_grade_subject ON video(grade, subject);
CREATE INDEX idx_handoff_grade_subject ON editor_handoff(grade, subject);
CREATE INDEX idx_raw_video_grade_subject ON raw_video(grade, subject);
```

#### 2. Update Subject Management
```sql
-- Remove unique constraint on subject.name to allow same subject across grades
ALTER TABLE subject DROP CONSTRAINT subject_name_key;

-- Add composite unique constraint for grade + subject
ALTER TABLE subject ADD CONSTRAINT subject_grade_name_unique UNIQUE (grade, name);
```

### Phase 2: Model Updates

#### 1. Update Database Models in app.py
```python
# Add grade field to all relevant models
class Video(db.Model):
    # ... existing fields ...
    grade = db.Column(db.Integer, nullable=False, default=4)

class RawVideo(db.Model):
    # ... existing fields ...
    grade = db.Column(db.Integer, nullable=False, default=4)

class EditorHandoff(db.Model):
    # ... existing fields ...
    grade = db.Column(db.Integer, nullable=False, default=4)

class ReviewCommentLog(db.Model):
    # ... existing fields ...
    grade = db.Column(db.Integer, nullable=False, default=4)

class SourceMaterial(db.Model):
    # ... existing fields ...
    grade = db.Column(db.Integer, nullable=False, default=4)

class QuickReviewItem(db.Model):
    # ... existing fields ...
    grade = db.Column(db.Integer, nullable=False, default=4)

class Subject(db.Model):
    # ... existing fields ...
    grade = db.Column(db.Integer, nullable=False, default=4)
    
    # Update unique constraint
    __table_args__ = (db.UniqueConstraint('grade', 'name', name='subject_grade_name_unique'),)
```

#### 2. Update Subject Seeding
```python
def seed_subjects():
    # Define subjects per grade
    grade_subjects = {
        1: ["Math", "English", "Science"],
        2: ["Math", "English", "Science", "Social Studies"],
        3: ["Math", "English", "Science", "Social Studies", "Art"],
        4: ["Math", "Physics", "Biology", "Chemistry", "Geography", "English"]
    }
    
    for grade, subjects in grade_subjects.items():
        for name in subjects:
            if not Subject.query.filter_by(grade=grade, name=name).first():
                db.session.add(Subject(name=name, grade=grade))
    db.session.commit()
```

### Phase 3: Application Logic Updates

#### 1. Update Query Patterns
```python
# Before: subject filtering
videos = Video.query.filter_by(subject='Math').all()

# After: grade + subject filtering  
videos = Video.query.filter_by(grade=4, subject='Math').all()
```

#### 2. Update Dashboard Logic
```python
# Update dashboard_home() function
@app.route('/dashboard_home')
def dashboard_home():
    # Add grade filter parameter
    grade_filter = request.args.get('grade', 4, type=int)
    
    # Update all queries to include grade
    total_subjects = Subject.query.filter_by(grade=grade_filter).count()
    pending_reviews = db.session.query(
        Video.subject, func.count(Video.id)
    ).filter(
        Video.status == 'Pending',
        Video.grade == grade_filter
    ).group_by(Video.subject).all()
```

#### 3. Update Forms and Templates
- Add grade selection dropdowns to all forms
- Update filters to include grade options
- Modify display logic to show grade context

### Phase 4: Data Migration Steps

#### 1. Run Flask-Migrate
```bash
flask db migrate -m "Add grade support to all tables"
flask db upgrade
```

#### 2. Seed New Grade Data
```python
# Run the updated seed function
with app.app_context():
    seed_subjects()
```

## Implementation Benefits

### ✅ Advantages
1. **Minimal Breaking Changes**: Existing Grade 4 data remains intact
2. **Scalable**: Easy to add more grades in future
3. **Performance**: Indexed grade+subject queries are fast
4. **Clear Separation**: Each grade can have different subjects
5. **Backward Compatible**: Default grade=4 maintains current functionality

### ⚠️ Considerations
1. **Form Updates**: All forms need grade selection
2. **Query Updates**: All queries need grade filtering
3. **UI Updates**: Templates need grade context
4. **Data Volume**: More data across grades

## Alternative Approaches (Not Recommended)

### Option 2: Hierarchical Subject Names
```python
# Less flexible, harder to query
subjects = ["Grade1_Math", "Grade2_Math", "Grade3_Math", "Grade4_Math"]
```

### Option 3: Separate Grade-Subject Mapping
```python
# More complex, requires additional joins
class GradeSubject(db.Model):
    grade = db.Column(db.Integer)
    subject_id = db.Column(db.Integer, db.ForeignKey('subject.id'))
```

## Conclusion
The **Add Grade Column** approach is the best choice because it:
- Maintains your current architecture
- Provides clear grade separation
- Allows different subjects per grade
- Has minimal migration complexity
- Scales well for future needs 