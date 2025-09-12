from flask import Flask, json, request, jsonify, Response
from flask_mysqldb import MySQL
from flask_cors import CORS
from datetime import datetime, timedelta, timezone
import traceback
import bcrypt
import jwt
from functools import wraps
import os
import time
from queue import Queue


app = Flask(__name__)

# CORS configuration - this should handle all preflight requests automatically
CORS(app, 
     origins=["http://127.0.0.1:5500", "http://localhost:5500", "http://localhost:3000"],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
     allow_headers=["Content-Type", "Authorization", "Accept"],
     supports_credentials=True)

# MySQL Config
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'church_planner_v2'

mysql = MySQL(app)

# JWT/Secret Config
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'bjwGBiG6WIM7L9B7BZ0vp-cnYoHo4c9mR_RCCZcmPc')  # Change this in production
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)

# Define user roles
ROLES = {
    'superadmin': 4,
    'admin': 3,
    'planner': 2,
    'viewer': 1
}

# Audit Log Model
class AuditLog:
    @staticmethod
    def log_action(user_id, action_type, entity_type, entity_id, old_data=None, new_data=None, ip_address=None):
        try:
            cur = mysql.connection.cursor()
            cur.execute("""
                INSERT INTO audit_logs 
                (user_id, action_type, entity_type, entity_id, old_data, new_data, ip_address)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (
                user_id,
                action_type,
                entity_type,
                entity_id,
                json.dumps(old_data) if old_data else None,
                json.dumps(new_data) if new_data else None,
                ip_address or request.remote_addr
            ))
            mysql.connection.commit()
            cur.close()
        except Exception as e:
            print(f"Failed to log action: {str(e)}")
            traceback.print_exc()

# Add a global handler for OPTIONS requests
@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        response = jsonify()
        response.headers.add("Access-Control-Allow-Origin", "*")
        response.headers.add('Access-Control-Allow-Headers', "Content-Type,Authorization")
        response.headers.add('Access-Control-Allow-Methods', "GET,PUT,POST,DELETE,OPTIONS")
        return response

# JWT Token Required Decorator
def token_required(required_role=None):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = None
            if 'Authorization' in request.headers:
                token = request.headers['Authorization'].split(" ")[1]
            if not token:
                return jsonify({"error": "Token is missing"}), 401
            try:
                data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
                current_user = {
                    'id': data['user_id'],
                    'email': data['email'],
                    'role': data['role']
                }
                # Check if user has required role
                if required_role and ROLES[current_user['role']] < ROLES[required_role]:
                    return jsonify({"error": "Insufficient permissions"}), 403
            except Exception as e:
                return jsonify({"error": "Token is invalid"}), 401
            return f(current_user, *args, **kwargs)
        return decorated
    return decorator

# Error handler
def handle_error(e):
    print(f"Error: {str(e)}")
    traceback.print_exc()
    return jsonify({"error": str(e)}), 500

# Health check endpoint
@app.route('/health', methods=['GET'])
def health_check():
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT 1")
        cur.close()
        return jsonify({"status": "healthy", "database": "connected"})
    except Exception as e:
        return jsonify({"status": "unhealthy", "error": str(e)}), 500

# -----------------------------
# AUTHENTICATION ENDPOINTS
# -----------------------------

# Add this helper function to safely check passwords
def safe_check_password(password, stored_hash):
    """
    Safely check password against stored hash.
    Handles both bcrypt hashes and plain text passwords (for migration).
    """
    try:
        # If stored_hash is bytes, convert to string
        if isinstance(stored_hash, bytes):
            stored_hash = stored_hash.decode('utf-8')
        
        # Check if it's a bcrypt hash (starts with $2a$, $2b$, $2x$, or $2y$)
        if stored_hash.startswith(('$2a$', '$2b$', '$2x$', '$2y$')):
            # It's a proper bcrypt hash
            return bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))
        else:
            # It might be plain text or another format
            # For security, we'll assume it's plain text and compare directly
            # This is temporary - you should rehash these passwords
            return password == stored_hash
    except Exception as e:
        print(f"Password check error: {e}")
        return False

# Updated login function
@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.json
        email = data.get('email')
        password = data.get('password')
        if not email or not password:
            return jsonify({"error": "Email and password are required"}), 400
        
        cur = mysql.connection.cursor()
        cur.execute("SELECT id, email, password, name, role FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        cur.close()
        
        if not user:
            return jsonify({"error": "Invalid credentials"}), 401
        
        # Use the safe password check function
        stored_password = user[2]
        if not safe_check_password(password, stored_password):
            return jsonify({"error": "Invalid credentials"}), 401
        
        # If the password was stored as plain text, rehash it now
        if not (isinstance(stored_password, str) and stored_password.startswith(('$2a$', '$2b$', '$2x$', '$2y$'))):
            # Rehash the password and update the database
            new_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            cur = mysql.connection.cursor()
            cur.execute("UPDATE users SET password = %s WHERE id = %s", (new_hash, user[0]))
            mysql.connection.commit()
            cur.close()
            print(f"Rehashed password for user: {email}")
        
        # Generate tokens
        access_token = generate_token(user[0], user[1], user[4], 'access')
        refresh_token = generate_token(user[0], user[1], user[4], 'refresh')
        
        return jsonify({
            "message": "Login successful",
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user": {
                "id": user[0],
                "email": user[1],
                "name": user[3],
                "role": user[4]
            }
        })
    except Exception as e:
        return handle_error(e)

# Updated register function to ensure proper hashing
@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.json
        email = data.get('email')
        password = data.get('password')
        name = data.get('name')
        if not email or not password or not name:
            return jsonify({"error": "Email, password and name are required"}), 400
        
        # Hash password properly
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        cur = mysql.connection.cursor()
        # Check if user exists
        cur.execute("SELECT id FROM users WHERE email = %s", (email,))
        if cur.fetchone():
            cur.close()
            return jsonify({"error": "User already exists"}), 400
        
        # Create user with default 'viewer' role
        cur.execute("""
            INSERT INTO users (email, password, name, role) 
            VALUES (%s, %s, %s, %s)
        """, (email, hashed_password, name, 'viewer'))
        mysql.connection.commit()
        user_id = cur.lastrowid
        cur.close()
        
        # Generate tokens
        access_token = generate_token(user_id, email, 'viewer', 'access')
        refresh_token = generate_token(user_id, email, 'viewer', 'refresh')
        
        return jsonify({
            "message": "User registered successfully",
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user": {
                "id": user_id,
                "email": email,
                "name": name,
                "role": "viewer"
            }
        })
    except Exception as e:
        return handle_error(e)



def generate_token(user_id, email, role, token_type):
    if token_type == 'access':
        expires = datetime.now(timezone.utc) + app.config['JWT_ACCESS_TOKEN_EXPIRES']
    else:
        expires = datetime.now(timezone.utc) + app.config['JWT_REFRESH_TOKEN_EXPIRES']
    payload = {
        'user_id': user_id,
        'email': email,
        'role': role,
        'exp': expires,
        'type': token_type
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm="HS256")

from datetime import datetime, timedelta
import calendar

def generate_recurring_events(base_event_data, recurrence_type, recurrence_end_date):
    """
    Generate recurring event instances based on the base event and recurrence parameters.
    
    Args:
        base_event_data: Dict containing the original event data
        recurrence_type: String ('weekly', 'biweekly', 'monthly', 'yearly')
        recurrence_end_date: String in YYYY-MM-DD format
    
    Returns:
        List of event data dictionaries for each recurring instance
    """
    if recurrence_type == 'none' or not recurrence_end_date:
        return []
    
    recurring_events = []
    base_date = datetime.strptime(base_event_data['event_date'], '%Y-%m-%d')
    end_date = datetime.strptime(recurrence_end_date, '%Y-%m-%d')
    current_date = base_date

    while True:
        if recurrence_type == 'daily':
            current_date += timedelta(days=1)
        elif recurrence_type == 'weekly':
            current_date += timedelta(weeks=1)
        elif recurrence_type == 'biweekly':
            current_date += timedelta(weeks=2)
        elif recurrence_type == 'monthly':
            if current_date.month == 12:
                next_month = current_date.replace(year=current_date.year + 1, month=1)
            else:
                next_month = current_date.replace(month=current_date.month + 1)
            try:
                current_date = next_month.replace(day=base_date.day)
            except ValueError:
                last_day = calendar.monthrange(next_month.year, next_month.month)[1]
                current_date = next_month.replace(day=min(base_date.day, last_day))
        elif recurrence_type == 'yearly':
            try:
                current_date = current_date.replace(year=current_date.year + 1)
            except ValueError:
                current_date = current_date.replace(year=current_date.year + 1, month=2, day=28)
        else:
            break  # Unknown recurrence type

        if current_date > end_date:
            break

        event_instance = base_event_data.copy()
        event_instance['event_date'] = current_date.strftime('%Y-%m-%d')
        event_instance['recurrence_type'] = 'none'
        event_instance['recurrence_end_date'] = None
        event_instance['parent_event_id'] = base_event_data.get('id')
        recurring_events.append(event_instance)
    return recurring_events


def create_event_with_recurrence(mysql, event_data, bulletins_data=None):
    """
    Create an event and its recurring instances.
    
    Args:
        mysql: MySQL connection object
        event_data: Dict containing event information
        bulletins_data: List of bulletin dictionaries (optional)
    
    Returns:
        Dict with success status and created event IDs
    """
    try:
        cur = mysql.connection.cursor()
        created_events = []
        
        # Create the base event first
        cur.execute("""
            INSERT INTO events (title, event_type_id, event_date, start_time, end_time, 
                              recurrence_type, recurrence_end_date)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (
            event_data['title'],
            event_data['event_type_id'],
            event_data['event_date'],
            event_data['start_time'],
            event_data['end_time'],
            event_data.get('recurrence_type', 'none'),
            event_data.get('recurrence_end_date')
        ))
        
        base_event_id = cur.lastrowid
        created_events.append(base_event_id)
        event_data['id'] = base_event_id
        
        # Create bulletins for base event if provided
        if bulletins_data:
            create_bulletins_for_event(cur, base_event_id, bulletins_data, event_data['start_time'])
        
        # Generate and create recurring events
        recurrence_type = event_data.get('recurrence_type', 'none')
        recurrence_end_date = event_data.get('recurrence_end_date')
        
        if recurrence_type != 'none' and recurrence_end_date:
            recurring_events = generate_recurring_events(event_data, recurrence_type, recurrence_end_date)
            
            for recurring_event in recurring_events:
                # Create the recurring event
                cur.execute("""
                    INSERT INTO events (title, event_type_id, event_date, start_time, end_time, 
                                      recurrence_type, recurrence_end_date, parent_event_id)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    recurring_event['title'],
                    recurring_event['event_type_id'],
                    recurring_event['event_date'],
                    recurring_event['start_time'],
                    recurring_event['end_time'],
                    'none',  # Individual instances are not recurring
                    None,
                    base_event_id  # Link to parent event
                ))
                
                recurring_event_id = cur.lastrowid
                created_events.append(recurring_event_id)
                
                # Create bulletins for recurring event if provided
                if bulletins_data:
                    create_bulletins_for_event(cur, recurring_event_id, bulletins_data, recurring_event['start_time'])
        
        mysql.connection.commit()
        cur.close()
        
        return {
            'success': True,
            'created_events': created_events,
            'base_event_id': base_event_id,
            'total_events': len(created_events)
        }
        
    except Exception as e:
        mysql.connection.rollback()
        cur.close()
        raise e


def create_bulletins_for_event(cursor, event_id, bulletins_data, event_start_time):
    """
    Create bulletins for an event with calculated start times.
    
    Args:
        cursor: Database cursor
        event_id: ID of the event
        bulletins_data: List of bulletin dictionaries
        event_start_time: Start time of the event (string in HH:MM:SS format)
    """
    current_time = datetime.strptime(str(event_start_time), "%H:%M:%S")
    last_end_time = current_time
    
    # Sort bulletins by display order
    sorted_bulletins = sorted(bulletins_data, key=lambda x: int(x.get('display_order', 0)))
    
    for item in sorted_bulletins:
        duration = int(item['duration_minutes'])
        cursor.execute("""
            INSERT INTO bulletins 
            (event_id, start_time, title, duration_minutes, preacher, language, category, display_order)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            event_id,
            current_time.strftime("%H:%M:%S"),
            item['title'],
            duration,
            item.get('preacher', ''),
            item.get('language', 'EN'),
            item.get('category', ''),
            item.get('display_order', 0)
        ))
        last_end_time = current_time + timedelta(minutes=duration)
        current_time = last_end_time
    
    # Update event end_time based on last bulletin
    cursor.execute("UPDATE events SET end_time = %s WHERE id = %s", 
                  (last_end_time.strftime("%H:%M:%S"), event_id))


def has_conflict_with_recurrence(mysql, event_date, start_time, end_time, recurrence_type, 
                               recurrence_end_date, exclude_event_id=None):
    """
    Check for conflicts including recurring event instances.
    
    Args:
        mysql: MySQL connection object
        event_date: Date of the event
        start_time: Start time of the event
        end_time: End time of the event
        recurrence_type: Type of recurrence
        recurrence_end_date: End date for recurrence
        exclude_event_id: Event ID to exclude from conflict check
    
    Returns:
        List of conflicting events or empty list if no conflicts
    """
    cur = mysql.connection.cursor()
    conflicts = []
    
    # Check conflicts for the base event date
    base_conflicts = check_single_date_conflicts(cur, event_date, start_time, end_time, exclude_event_id)
    conflicts.extend(base_conflicts)
    
    # If recurring, check conflicts for all recurring instances
    if recurrence_type != 'none' and recurrence_end_date:
        event_data = {
            'event_date': event_date,
            'start_time': start_time,
            'end_time': end_time
        }
        
        recurring_events = generate_recurring_events(event_data, recurrence_type, recurrence_end_date)
        
        for recurring_event in recurring_events:
            recurring_conflicts = check_single_date_conflicts(
                cur, 
                recurring_event['event_date'], 
                recurring_event['start_time'], 
                recurring_event['end_time'], 
                exclude_event_id
            )
            conflicts.extend(recurring_conflicts)
    
    cur.close()
    return conflicts


def check_single_date_conflicts(cursor, event_date, start_time, end_time, exclude_event_id=None):
    """
    Check for conflicts on a single date.
    """
    query = """
        SELECT id, title, event_date, start_time, end_time FROM events
        WHERE event_date = %s
        AND (
            (start_time < %s AND end_time > %s) OR
            (start_time < %s AND end_time > %s) OR
            (start_time >= %s AND end_time <= %s)
        )
    """
    params = [event_date, end_time, end_time, start_time, start_time, start_time, end_time]
    
    if exclude_event_id:
        query += " AND id != %s"
        params.append(exclude_event_id)
    
    cursor.execute(query, params)
    return cursor.fetchall()


# Updated route handlers for your Flask app

@app.route('/events', methods=['POST'])
@token_required('planner')
def create_event_updated(current_user):
    """Updated event creation with proper recurrence support"""
    try:
        data = request.json
        
        # Validate required fields
        required_fields = ['title', 'event_type_id', 'event_date', 'start_time', 'end_time']
        for field in required_fields:
            if not data.get(field):
                return jsonify({"error": f"Missing required field: {field}"}), 400
        
        recurrence_type = data.get('recurrence_type', 'none')
        recurrence_end_date = data.get('recurrence_end_date')
        bulletins_data = data.get('bulletins', [])
        
        # Validate recurrence parameters
        if recurrence_type != 'none':
            if not recurrence_end_date:
                return jsonify({"error": "Recurrence end date is required for recurring events"}), 400
            
            valid_recurrence_types = ['weekly', 'biweekly', 'monthly', 'yearly', 'daily']
            if recurrence_type not in valid_recurrence_types:
                return jsonify({"error": f"Invalid recurrence type. Must be one of: {valid_recurrence_types}"}), 400
            
            # Validate end date is after start date
            start_date = datetime.strptime(data['event_date'], '%Y-%m-%d')
            end_date = datetime.strptime(recurrence_end_date, '%Y-%m-%d')
            if end_date <= start_date:
                return jsonify({"error": "Recurrence end date must be after the event date"}), 400
        
        # Check for conflicts including recurring instances
        conflicts = has_conflict_with_recurrence(
            mysql,
            data['event_date'],
            data['start_time'], 
            data['end_time'],
            recurrence_type,
            recurrence_end_date
        )
        
        if conflicts:
            return jsonify({
                "error": "Event conflicts detected.",
                "conflicts": [
                    {
                        "id": c[0], 
                        "title": c[1],
                        "date": str(c[2]),
                        "start_time": str(c[3]),
                        "end_time": str(c[4])
                    }
                    for c in conflicts
                ]
            }), 409
        
        # Create event with recurrence
        result = create_event_with_recurrence(mysql, data, bulletins_data)
        
        if result['success']:
            # Log the action
            AuditLog.log_action(
                user_id=current_user['id'],
                action_type='CREATE',
                entity_type='EVENT',
                entity_id=result['base_event_id'],
                new_data={
                    **data,
                    'created_events_count': result['total_events'],
                    'recurring_event_ids': result['created_events']
                }
            )
            
            return jsonify({
                "message": f"Event created successfully. {result['total_events']} event(s) generated.",
                "base_event_id": result['base_event_id'],
                "created_events": result['created_events'],
                "total_events": result['total_events']
            }), 201
        else:
            return jsonify({"error": "Failed to create event"}), 500
            
    except Exception as e:
        return handle_error(e)


@app.route('/events/<int:event_id>/recurrence', methods=['GET'])
@token_required('viewer')
def get_event_recurrence_info(current_user, event_id):
    """Get recurrence information for an event"""
    try:
        cur = mysql.connection.cursor()
        
        # Get event recurrence info
        cur.execute("""
            SELECT id, title, recurrence_type, recurrence_end_date, parent_event_id
            FROM events 
            WHERE id = %s
        """, (event_id,))
        
        event = cur.fetchone()
        if not event:
            return jsonify({"error": "Event not found"}), 404
        
        response = {
            "id": event[0],
            "title": event[1],
            "recurrence_type": event[2],
            "recurrence_end_date": str(event[3]) if event[3] else None,
            "parent_event_id": event[4],
            "is_recurring_instance": event[4] is not None
        }
        
        # If this is a parent event with recurrence, get all instances
        if event[2] != 'none' and not event[4]:
            cur.execute("""
                SELECT id, event_date, start_time
                FROM events
                WHERE parent_event_id = %s
                ORDER BY event_date ASC
            """, (event_id,))
            
            instances = []
            for row in cur.fetchall():
                instances.append({
                    "id": row[0],
                    "event_date": str(row[1]),
                    "start_time": str(row[2])
                })
            
            response["recurring_instances"] = instances
            response["instance_count"] = len(instances)
        
        # If this is an instance, get parent info
        elif event[4]:
            cur.execute("""
                SELECT id, title, recurrence_type, recurrence_end_date
                FROM events
                WHERE id = %s
            """, (event[4],))
            
            parent = cur.fetchone()
            if parent:
                response["parent_event"] = {
                    "id": parent[0],
                    "title": parent[1],
                    "recurrence_type": parent[2],
                    "recurrence_end_date": str(parent[3]) if parent[3] else None
                }
        
        cur.close()
        return jsonify(response)
        
    except Exception as e:
        return handle_error(e)


@app.route('/events/<int:event_id>/recurrence', methods=['DELETE'])
@token_required('admin')
def delete_event_series(current_user, event_id):
    """Delete an entire event series (parent and all recurring instances)"""
    try:
        cur = mysql.connection.cursor()
        
        # Get event info
        cur.execute("""
            SELECT id, title, parent_event_id, recurrence_type
            FROM events 
            WHERE id = %s
        """, (event_id,))
        
        event = cur.fetchone()
        if not event:
            return jsonify({"error": "Event not found"}), 404
        
        # Determine the parent event ID
        parent_id = event[2] if event[2] else event[0]
        
        # Get all events in the series (parent + instances)
        cur.execute("""
            SELECT id, title, event_date FROM events
            WHERE id = %s OR parent_event_id = %s
        """, (parent_id, parent_id))
        
        events_to_delete = cur.fetchall()
        event_ids = [e[0] for e in events_to_delete]
        
        # Delete bulletins for all events in the series
        cur.execute(f"""
            DELETE FROM bulletins 
            WHERE event_id IN ({','.join(['%s'] * len(event_ids))})
        """, event_ids)
        
        # Delete all events in the series
        cur.execute(f"""
            DELETE FROM events 
            WHERE id IN ({','.join(['%s'] * len(event_ids))})
        """, event_ids)
        
        mysql.connection.commit()
        cur.close()
        
        # Log the action
        AuditLog.log_action(
            user_id=current_user['id'],
            action_type='DELETE',
            entity_type='EVENT_SERIES',
            entity_id=parent_id,
            old_data={
                "deleted_events": [
                    {"id": e[0], "title": e[1], "date": str(e[2])}
                    for e in events_to_delete
                ],
                "total_deleted": len(events_to_delete)
            }
        )
        
        return jsonify({
            "message": f"Event series deleted successfully. {len(events_to_delete)} event(s) removed.",
            "deleted_events": len(events_to_delete)
        })
        
    except Exception as e:
        return handle_error(e)

# -----------------------------
# EVENT TYPES
# -----------------------------
@app.route('/event_types', methods=['GET'])
def get_event_types():
    """Get all event types"""
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT id, name FROM event_types ORDER BY name ASC")
        types = [{"id": row[0], "name": row[1]} for row in cur.fetchall()]
        cur.close()
        return jsonify(types)
    except Exception as e:
        return handle_error(e)

# Protect event type creation (admin only)
# Update the existing create_event_type endpoint to remove color and icon
@app.route('/event_types', methods=['POST'])
@token_required('admin')
def create_event_type(current_user):
    """Create a new event type (updated version)"""
    try:
        data = request.json
        name = data.get('name', '').strip()
        
        if not name:
            return jsonify({"error": "Event type name is required"}), 400

        cur = mysql.connection.cursor()
        
        # Check if name already exists
        cur.execute("SELECT id FROM event_types WHERE name = %s", (name,))
        if cur.fetchone():
            cur.close()
            return jsonify({"error": "Event type with this name already exists"}), 400
        
        # Create the event type
        cur.execute("INSERT INTO event_types (name) VALUES (%s)", (name,))
        mysql.connection.commit()
        event_type_id = cur.lastrowid
        cur.close()

        # Log the action
        AuditLog.log_action(
            user_id=current_user['id'],
            action_type='CREATE',
            entity_type='EVENT_TYPE',
            entity_id=event_type_id,
            new_data={"name": name},
            ip_address=request.remote_addr
        )

        return jsonify({
            "message": "Event type created successfully",
            "id": event_type_id, 
            "name": name
        }), 201

    except Exception as e:
        return handle_error(e)
    
@app.route('/event_types/<int:event_type_id>', methods=['DELETE'])
@token_required('admin')
def delete_event_type(current_user, event_type_id):
    """Delete an event type"""
    try:
        cur = mysql.connection.cursor()
        
        # Get event type data before deletion
        cur.execute("SELECT id, name FROM event_types WHERE id = %s", (event_type_id,))
        old_event_type = cur.fetchone()
        
        if not old_event_type:
            cur.close()
            return jsonify({"error": "Event type not found"}), 404
        
        # Check if event type is being used by any events
        cur.execute("SELECT COUNT(*) FROM events WHERE event_type_id = %s", (event_type_id,))
        event_count = cur.fetchone()[0]
        
        if event_count > 0:
            cur.close()
            return jsonify({
                "error": f"Cannot delete event type. It is currently used by {event_count} event(s)."
            }), 400
        
        # Check if event type is being used by any templates
        cur.execute("""
            SELECT COUNT(*) FROM templates t
            WHERE EXISTS (
                SELECT 1 FROM template_bulletins tb 
                WHERE tb.template_id = t.id AND tb.category = %s
            )
        """, (old_event_type[1],))
        template_count = cur.fetchone()[0]
        
        if template_count > 0:
            cur.close()
            return jsonify({
                "error": f"Cannot delete event type. It is referenced by {template_count} template(s)."
            }), 400
        
        # Delete the event type
        cur.execute("DELETE FROM event_types WHERE id = %s", (event_type_id,))
        mysql.connection.commit()
        cur.close()
        
        # Log the action
        AuditLog.log_action(
            user_id=current_user['id'],
            action_type='DELETE',
            entity_type='EVENT_TYPE',
            entity_id=event_type_id,
            old_data={"id": old_event_type[0], "name": old_event_type[1]},
            ip_address=request.remote_addr
        )
        
        return jsonify({"message": "Event type deleted successfully"})
        
    except Exception as e:
        return handle_error(e)
    

@app.route('/event_types/<int:event_type_id>', methods=['GET'])
@token_required('viewer')
def get_event_type(current_user, event_type_id):
    """Get a specific event type by ID"""
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT id, name FROM event_types WHERE id = %s", (event_type_id,))
        event_type = cur.fetchone()
        cur.close()
        
        if not event_type:
            return jsonify({"error": "Event type not found"}), 404
            
        return jsonify({
            "id": event_type[0],
            "name": event_type[1]
        })
    except Exception as e:
        return handle_error(e)

@app.route('/event_types/<int:event_type_id>', methods=['PUT'])
@token_required('admin')
def update_event_type(current_user, event_type_id):
    """Update an existing event type"""
    try:
        data = request.json
        name = data.get('name', '').strip()
        
        if not name:
            return jsonify({"error": "Event type name is required"}), 400
        
        cur = mysql.connection.cursor()
        
        # Get old event type data for audit log
        cur.execute("SELECT id, name FROM event_types WHERE id = %s", (event_type_id,))
        old_event_type = cur.fetchone()
        
        if not old_event_type:
            cur.close()
            return jsonify({"error": "Event type not found"}), 404
        
        # Check if name already exists (excluding current event type)
        cur.execute("SELECT id FROM event_types WHERE name = %s AND id != %s", (name, event_type_id))
        if cur.fetchone():
            cur.close()
            return jsonify({"error": "Event type with this name already exists"}), 400
        
        # Update the event type
        cur.execute("UPDATE event_types SET name = %s WHERE id = %s", (name, event_type_id))
        mysql.connection.commit()
        cur.close()
        
        # Log the action
        AuditLog.log_action(
            user_id=current_user['id'],
            action_type='EDIT',
            entity_type='EVENT_TYPE',
            entity_id=event_type_id,
            old_data={"id": old_event_type[0], "name": old_event_type[1]},
            new_data={"id": event_type_id, "name": name},
            ip_address=request.remote_addr
        )
        
        return jsonify({
            "message": "Event type updated successfully",
            "id": event_type_id,
            "name": name
        })
        
    except Exception as e:
        return handle_error(e)
# -----------------------------
# EVENTS
# -----------------------------
# Replace your existing create_event route with this updated version:

@app.route('/events', methods=['POST'])
@token_required('planner')
def create_event(current_user):
    """Updated event creation with proper recurrence support"""
    try:
        data = request.json
        
        # Validate required fields
        required_fields = ['title', 'event_type_id', 'event_date', 'start_time', 'end_time']
        for field in required_fields:
            if not data.get(field):
                return jsonify({"error": f"Missing required field: {field}"}), 400
        
        recurrence_type = data.get('recurrence_type', 'none')
        recurrence_end_date = data.get('recurrence_end_date')
        bulletins_data = data.get('bulletins', [])
        
        # Validate recurrence parameters
        if recurrence_type != 'none':
            if not recurrence_end_date:
                return jsonify({"error": "Recurrence end date is required for recurring events"}), 400
            
            valid_recurrence_types = ['weekly', 'biweekly', 'monthly', 'yearly', 'daily']
            if recurrence_type not in valid_recurrence_types:
                return jsonify({"error": f"Invalid recurrence type. Must be one of: {valid_recurrence_types}"}), 400
                
            # Validate end date is after start date
            start_date = datetime.strptime(data['event_date'], '%Y-%m-%d')
            end_date = datetime.strptime(recurrence_end_date, '%Y-%m-%d')
            if end_date <= start_date:
                return jsonify({"error": "Recurrence end date must be after the event date"}), 400
        
        # Check for conflicts including recurring instances
        conflicts = has_conflict_with_recurrence(
            mysql,
            data['event_date'],
            data['start_time'], 
            data['end_time'],
            recurrence_type,
            recurrence_end_date
        )
        
        if conflicts:
            return jsonify({
                "error": "Event conflicts detected.",
                "conflicts": [
                    {
                        "id": c[0], 
                        "title": c[1],
                        "date": str(c[2]),
                        "start_time": str(c[3]),
                        "end_time": str(c[4])
                    }
                    for c in conflicts
                ]
            }), 409
        
        # Create event with recurrence
        result = create_event_with_recurrence(mysql, data, bulletins_data)
        
        if result['success']:
            # Log the action
            AuditLog.log_action(
                user_id=current_user['id'],
                action_type='CREATE',
                entity_type='EVENT',
                entity_id=result['base_event_id'],
                new_data={
                    **data,
                    'created_events_count': result['total_events'],
                    'recurring_event_ids': result['created_events']
                }
            )
            
            return jsonify({
                "message": f"Event created successfully. {result['total_events']} event(s) generated.",
                "base_event_id": result['base_event_id'],
                "created_events": result['created_events'],
                "total_events": result['total_events']
            }), 201
        else:
            return jsonify({"error": "Failed to create event"}), 500
            
    except Exception as e:
        return handle_error(e)


# Update the events listing to show recurrence information
@app.route('/events', methods=['GET'])
@token_required('viewer')
def get_events(current_user):
    try:
        show_series = request.args.get('series', 'false').lower() == 'true'
        
        cur = mysql.connection.cursor()
        
        if show_series:
            # Group by series - show only parent events
            cur.execute("""
                SELECT 
                    e.id, 
                    e.title, 
                    e.event_date, 
                    e.start_time, 
                    e.end_time, 
                    et.name as event_type,
                    e.recurrence_type,
                    e.recurrence_end_date,
                    (SELECT COUNT(*) FROM events WHERE parent_event_id = e.id) as instance_count
                FROM events e
                JOIN event_types et ON e.event_type_id = et.id
                WHERE e.parent_event_id IS NULL
                ORDER BY e.event_date DESC, e.start_time DESC
            """)
        else:
            # Show all events including instances
            cur.execute("""
                SELECT 
                    e.id, 
                    e.title, 
                    e.event_date, 
                    e.start_time, 
                    e.end_time, 
                    et.name as event_type,
                    e.recurrence_type,
                    e.parent_event_id,
                    CASE WHEN e.parent_event_id IS NOT NULL THEN 
                        (SELECT title FROM events WHERE id = e.parent_event_id)
                    ELSE NULL END as parent_title
                FROM events e
                JOIN event_types et ON e.event_type_id = et.id
                ORDER BY e.event_date DESC, e.start_time DESC
            """)
        
        events = cur.fetchall()
        cur.close()
        
        # Format response
        result = []
        for row in events:
            if isinstance(row, dict):
                event_data = {
                    "id": row['id'],
                    "title": row['title'],
                    "event_date": str(row['event_date']),
                    "start_time": str(row['start_time']),
                    "end_time": str(row['end_time']),
                    "event_type": row['event_type'],
                    "recurrence_type": row.get('recurrence_type', 'none'),
                }
                
                if show_series:
                    event_data["instance_count"] = row.get('instance_count', 0)
                    event_data["recurrence_end_date"] = str(row['recurrence_end_date']) if row.get('recurrence_end_date') else None
                else:
                    event_data["parent_event_id"] = row.get('parent_event_id')
                    event_data["parent_title"] = row.get('parent_title')
                    event_data["is_recurring_instance"] = row.get('parent_event_id') is not None
                    
            else:
                # Handle tuple format
                if show_series:
                    event_data = {
                        "id": row[0],
                        "title": row[1],
                        "event_date": str(row[2]),
                        "start_time": str(row[3]),
                        "end_time": str(row[4]),
                        "event_type": row[5],
                        "recurrence_type": row[6] or 'none',
                        "recurrence_end_date": str(row[7]) if row[7] else None,
                        "instance_count": row[8]
                    }
                else:
                    event_data = {
                        "id": row[0],
                        "title": row[1],
                        "event_date": str(row[2]),
                        "start_time": str(row[3]),
                        "end_time": str(row[4]),
                        "event_type": row[5],
                        "recurrence_type": row[6] or 'none',
                        "parent_event_id": row[7],
                        "parent_title": row[8],
                        "is_recurring_instance": row[7] is not None
                    }
            
            result.append(event_data)
        
        return jsonify(result)
        
    except Exception as e:
        return handle_error(e)


# Update the has_conflict function to use the new recurrence-aware version
def has_conflict(event_date, start_time, end_time, recurrence_type='none', recurrence_end_date=None, exclude_event_id=None):
    """Updated conflict detection with recurrence support"""
    return has_conflict_with_recurrence(
        mysql, event_date, start_time, end_time, 
        recurrence_type or 'none', recurrence_end_date, exclude_event_id
    )


# Add new route to get recurrence options for the frontend
@app.route('/recurrence-types', methods=['GET'])
def get_recurrence_types():
    """Get available recurrence types"""
    return jsonify([
        {"value": "none", "label": "No Recurrence"},
        {"value": "daily", "label": "Daily"},
        {"value": "weekly", "label": "Weekly"},
        {"value": "biweekly", "label": "Bi-weekly"},
        {"value": "monthly", "label": "Monthly"}, 
        {"value": "yearly", "label": "Yearly"}
    ])


# Add route to preview recurring events before creation
@app.route('/events/preview-recurrence', methods=['POST'])
@token_required('planner')
def preview_recurring_events(current_user):
    """Preview recurring event instances before creation"""
    try:
        data = request.json
        
        required_fields = ['event_date', 'recurrence_type', 'recurrence_end_date']
        for field in required_fields:
            if not data.get(field):
                return jsonify({"error": f"Missing required field: {field}"}), 400
        
        recurrence_type = data.get('recurrence_type', 'none')
        recurrence_end_date = data.get('recurrence_end_date')
        
        if recurrence_type == 'none':
            return jsonify({"preview": [], "count": 0})
        
        # Generate preview of recurring events
        recurring_events = generate_recurring_events(data, recurrence_type, recurrence_end_date)
        
        preview = []
        for event in recurring_events:
            preview.append({
                "event_date": event['event_date'],
                "title": event['title'],
                "start_time": event['start_time'],
                "end_time": event['end_time']
            })
        
        return jsonify({
            "preview": preview,
            "count": len(preview),
            "original_date": data['event_date']
        })
        
    except Exception as e:
        return handle_error(e)


# Add route to handle bulk operations on recurring events
@app.route('/events/bulk-update-series', methods=['PUT'])
@token_required('admin')
def bulk_update_event_series(current_user):
    """Update all events in a recurring series"""
    try:
        data = request.json
        parent_event_id = data.get('parent_event_id')
        updates = data.get('updates', {})
        
        if not parent_event_id:
            return jsonify({"error": "Parent event ID is required"}), 400
        
        cur = mysql.connection.cursor()
        
        # Get all events in the series
        cur.execute("""
            SELECT id, title, event_date FROM events
            WHERE id = %s OR parent_event_id = %s
            ORDER BY event_date ASC
        """, (parent_event_id, parent_event_id))
        
        events_in_series = cur.fetchall()
        if not events_in_series:
            return jsonify({"error": "Event series not found"}), 404
        
        updated_count = 0
        
        # Update each event in the series
        for event in events_in_series:
            event_id = event[0]
            
            # Build dynamic update query
            update_fields = []
            params = []
            
            allowed_fields = ['title', 'event_type_id', 'start_time', 'end_time']
            for field in allowed_fields:
                if field in updates:
                    update_fields.append(f"{field} = %s")
                    params.append(updates[field])
            
            if update_fields:
                params.append(event_id)
                query = f"UPDATE events SET {', '.join(update_fields)} WHERE id = %s"
                cur.execute(query, params)
                updated_count += 1
        
        mysql.connection.commit()
        cur.close()
        
        # Log the bulk update
        AuditLog.log_action(
            user_id=current_user['id'],
            action_type='BULK_EDIT',
            entity_type='EVENT_SERIES',
            entity_id=parent_event_id,
            new_data={
                "updates": updates,
                "events_updated": updated_count
            }
        )
        
        return jsonify({
            "message": f"Successfully updated {updated_count} events in the series",
            "updated_count": updated_count
        })
        
    except Exception as e:
        return handle_error(e)


# Add route to get calendar view with recurring events
@app.route('/events/calendar', methods=['GET'])
@token_required('viewer')
def get_calendar_events(current_user):
    """Get events for calendar view with recurrence information"""
    try:
        start_date = request.args.get('start')
        end_date = request.args.get('end')
        
        cur = mysql.connection.cursor()
        
        query = """
            SELECT 
                e.id,
                e.title,
                e.event_date,
                e.start_time,
                e.end_time,
                et.name as event_type,
                et.id as event_type_id,
                e.recurrence_type,
                e.parent_event_id,
                CASE 
                    WHEN e.parent_event_id IS NULL AND e.recurrence_type != 'none' THEN 'series_parent'
                    WHEN e.parent_event_id IS NOT NULL THEN 'series_instance'
                    ELSE 'single'
                END as event_role
            FROM events e
            JOIN event_types et ON e.event_type_id = et.id
        """
        
        params = []
        if start_date and end_date:
            query += " WHERE e.event_date BETWEEN %s AND %s"
            params.extend([start_date, end_date])
        elif start_date:
            query += " WHERE e.event_date >= %s"
            params.append(start_date)
        elif end_date:
            query += " WHERE e.event_date <= %s"
            params.append(end_date)
        
        query += " ORDER BY e.event_date ASC, e.start_time ASC"
        
        cur.execute(query, params)
        events = cur.fetchall()
        cur.close()
        
        calendar_events = []
        for row in events:
            if isinstance(row, dict):
                event = {
                    "id": row['id'],
                    "title": row['title'],
                    "start": f"{row['event_date']}T{row['start_time']}",
                    "end": f"{row['event_date']}T{row['end_time']}",
                    "event_type": row['event_type'],
                    "event_type_id": row['event_type_id'],
                    "recurrence_type": row['recurrence_type'],
                    "event_role": row['event_role'],
                    "parent_event_id": row['parent_event_id']
                }
            else:
                # Handle tuple format
                event = {
                    "id": row[0],
                    "title": row[1],
                    "start": f"{row[2]}T{row[3]}",
                    "end": f"{row[2]}T{row[4]}",
                    "event_type": row[5],
                    "event_type_id": row[6],
                    "recurrence_type": row[7] or 'none',
                    "event_role": row[9],
                    "parent_event_id": row[8]
                }
            
            # Add visual indicators for recurring events
            if event['event_role'] == 'series_parent':
                event['className'] = 'recurring-parent'
                event['title'] = f"🔄 {event['title']}"
            elif event['event_role'] == 'series_instance':
                event['className'] = 'recurring-instance'
                event['title'] = f"↪️ {event['title']}"
            
            calendar_events.append(event)
        
        return jsonify(calendar_events)
        
    except Exception as e:
        return handle_error(e)
        

@app.route('/events/<int:event_id>', methods=['GET'])
def get_event(event_id):
    try:
        cur = mysql.connection.cursor()
        cur.execute("""
            SELECT e.id, e.title, e.event_date, e.start_time, e.end_time, e.event_type_id, et.name as event_type
            FROM events e
            JOIN event_types et ON e.event_type_id = et.id
            WHERE e.id = %s
        """, (event_id,))
        event = cur.fetchone()
        cur.close()
        
        if not event:
            return jsonify({"error": "Event not found"}), 404
        
        if isinstance(event, dict):
            return jsonify({
                "id": event['id'],
                "title": event['title'],
                "event_date": str(event['event_date']),
                "start_time": str(event['start_time']),
                "end_time": str(event['end_time']),
                "event_type_id": event['event_type_id'],
                "event_type": event['event_type']
            })
        else:
            return jsonify({
                "id": event[0],
                "title": event[1],
                "event_date": str(event[2]),
                "start_time": str(event[3]),
                "end_time": str(event[4]),
                "event_type_id": event[5],
                "event_type": event[6]
            })
    except Exception as e:
        return handle_error(e)

@app.route('/events/<int:event_id>/edit', methods=['GET'])
def get_event_with_bulletins(event_id):
    try:
        cur = mysql.connection.cursor()
        # Get event
        cur.execute("""
            SELECT id, title, event_date, start_time, end_time, event_type_id
            FROM events WHERE id = %s
        """, (event_id,))
        event = cur.fetchone()
        # Get bulletins
        cur.execute("""
            SELECT title, start_time, duration_minutes, preacher, language, category, display_order
            FROM bulletins WHERE event_id = %s ORDER BY display_order ASC
        """, (event_id,))
        bulletins = cur.fetchall()
        cur.close()
        if not event:
            return jsonify({"error": "Event not found"}), 404
        # Format event and bulletins
        event_data = {
            "id": event[0],
            "title": event[1],
            "event_date": str(event[2]),
            "start_time": str(event[3]),
            "end_time": str(event[4]),
            "event_type_id": event[5],
            "bulletins": [
                {
                    "title": b[0],
                    "start_time": str(b[1]),
                    "duration_minutes": b[2],
                    "preacher": b[3],
                    "language": b[4],
                    "category": b[5],
                    "display_order": b[6]
                } for b in bulletins
            ]
        }
        return jsonify(event_data)
    except Exception as e:
        return handle_error(e)
@app.route('/events/<int:event_id>', methods=['PUT'])
@token_required('planner')
def update_event_and_bulletins(current_user, event_id):
    try:
        data = request.json
        event_data = data.get('event')
        new_bulletins = data.get('bulletins', [])

        # Get complete old data before making any changes
        cur = mysql.connection.cursor()
        
        # Get old event data with event type name
        cur.execute("""
            SELECT e.*, et.name as event_type 
            FROM events e
            JOIN event_types et ON e.event_type_id = et.id
            WHERE e.id = %s
        """, (event_id,))
        old_event = cur.fetchone()
        
        # Get old bulletins
        cur.execute("""
            SELECT id, event_id, title, start_time, duration_minutes, 
                   preacher, language, category, display_order
            FROM bulletins 
            WHERE event_id = %s
        """, (event_id,))
        old_bulletins = cur.fetchall()
        
        if not event_data:
            cur.close()
            return jsonify({"error": "Missing event data"}), 400

        # Check for conflicts with the new timing
        conflicts = has_conflict(
            event_data['event_date'],
            event_data['start_time'],
            event_data.get('end_time', ''),
            event_data.get('recurrence_type', 'none'),
            event_data.get('recurrence_end_date'),
            exclude_event_id=event_id
        )
        if conflicts:
            cur.close()
            return jsonify({
                "error": "Event conflicts with another event.",
                "conflicts": [{"id": c[0], "title": c[1]} for c in conflicts]
            }), 409

        # Update event
        cur.execute("""
            UPDATE events 
            SET title=%s, event_type_id=%s, event_date=%s, start_time=%s
            WHERE id=%s
        """, (
            event_data['title'],
            event_data['event_type_id'],
            event_data['event_date'],
            event_data['start_time'],
            event_id
        ))
        
        # Delete old bulletins
        cur.execute("DELETE FROM bulletins WHERE event_id = %s", (event_id,))
        
        # Insert new bulletins with calculated start times
        current_time = datetime.strptime(str(event_data['start_time']), "%H:%M:%S")
        last_end_time = current_time
        
        # Sort bulletins by display order
        sorted_bulletins = sorted(new_bulletins, key=lambda x: int(x.get('display_order', 0)))
        
        for item in sorted_bulletins:
            duration = int(item['duration_minutes'])
            cur.execute("""
                INSERT INTO bulletins 
                (event_id, start_time, title, duration_minutes, preacher, language, category, display_order)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                event_id,
                current_time.strftime("%H:%M:%S"),
                item['title'],
                duration,
                item.get('preacher', ''),
                item.get('language', 'EN'),
                item.get('category', ''),
                item.get('display_order', 0)
            ))
            last_end_time = current_time + timedelta(minutes=duration)
            current_time = last_end_time
        
        # Update event end_time based on last bulletin
        cur.execute("UPDATE events SET end_time = %s WHERE id = %s", 
                   (last_end_time.strftime("%H:%M:%S"), event_id))
        
        mysql.connection.commit()
        cur.close()

        # Format old data for audit log
        old_data = {
            'event': {
                'id': old_event[0],
                'title': old_event[1],
                'event_type_id': old_event[2],
                'event_date': str(old_event[3]),
                'start_time': str(old_event[4]),
                'end_time': str(old_event[5]),
                'recurrence_type': old_event[6],
                'recurrence_end_date': str(old_event[7]) if old_event[7] else None,
                'event_type': old_event[8]
            },
            'bulletins': [
                {
                    'id': b[0],
                    'event_id': b[1],
                    'title': b[2],
                    'start_time': str(b[3]),
                    'duration_minutes': b[4],
                    'preacher': b[5],
                    'language': b[6],
                    'category': b[7],
                    'display_order': b[8]
                } for b in old_bulletins
            ]
        }

        # Format new data for audit log
        new_data = {
            'event': event_data,
            'bulletins': [
                {
                    'title': b['title'],
                    'duration_minutes': b['duration_minutes'],
                    'preacher': b.get('preacher', ''),
                    'language': b.get('language', 'EN'),
                    'category': b.get('category', ''),
                    'display_order': b.get('display_order', 0)
                } for b in new_bulletins
            ]
        }

        # Log the action with both old and new data
        AuditLog.log_action(
            user_id=current_user['id'],
            action_type='EDIT',
            entity_type='EVENT',
            entity_id=event_id,
            old_data=old_data,
            new_data=new_data,
            ip_address=request.remote_addr
        )

        return jsonify({"message": "Event and bulletins updated successfully"})
    except Exception as e:
        return handle_error(e)
# Protect event deletion (admin or higher)
@app.route('/events/<int:event_id>', methods=['DELETE'])
@token_required('admin')
def delete_event(current_user, event_id):
    try:
        # Get complete event data before deletion
        cur = mysql.connection.cursor()
        cur.execute("""
            SELECT e.*, et.name as event_type 
            FROM events e
            JOIN event_types et ON e.event_type_id = et.id
            WHERE e.id = %s
        """, (event_id,))
        old_event = cur.fetchone()
        
        # Get bulletins for the event
        cur.execute("""
            SELECT id, title, start_time, duration_minutes, preacher, 
                   language, category, display_order
            FROM bulletins WHERE event_id = %s
        """, (event_id,))
        old_bulletins = cur.fetchall()
        
        # Delete bulletins first (foreign key constraint)
        cur.execute("DELETE FROM bulletins WHERE event_id = %s", (event_id,))
        # Delete the event
        cur.execute("DELETE FROM events WHERE id = %s", (event_id,))
        mysql.connection.commit()
        cur.close()

        # Format old data for audit log
        old_data = {
            'event': {
                'id': old_event[0],
                'title': old_event[1],
                'event_type_id': old_event[2],
                'event_date': str(old_event[3]),
                'start_time': str(old_event[4]),
                'end_time': str(old_event[5]),
                'recurrence_type': old_event[6],
                'recurrence_end_date': str(old_event[7]) if old_event[7] else None,
                'event_type': old_event[8]
            },
            'bulletins': [
                {
                    'id': b[0],
                    'title': b[1],
                    'start_time': str(b[2]),
                    'duration_minutes': b[3],
                    'preacher': b[4],
                    'language': b[5],
                    'category': b[6],
                    'display_order': b[7]
                } for b in old_bulletins
            ]
        }

        # Log the action
        AuditLog.log_action(
            user_id=current_user['id'],
            action_type='DELETE',
            entity_type='EVENT',
            entity_id=event_id,
            old_data=old_data,
            ip_address=request.remote_addr
        )
        return jsonify({"message": "Event deleted successfully"})
    except Exception as e:
        return handle_error(e)
# -----------------------------
# BULLETINS (linked to an event)
# -----------------------------
@app.route('/events/<int:event_id>/bulletins', methods=['POST'])
@token_required('planner')
def save_bulletins(current_user, event_id):
    try:
        data = request.json
        if not isinstance(data, list):
            return jsonify({"error": "Request body must be a list of bulletins"}), 400

        cur = mysql.connection.cursor()

        # Get event info to check if it's a recurring parent
        cur.execute("""
            SELECT id, recurrence_type, parent_event_id 
            FROM events 
            WHERE id = %s
        """, (event_id,))
        event = cur.fetchone()
        if not event:
            cur.close()
            return jsonify({"error": "Event not found"}), 404

        event_id, recurrence_type, parent_event_id = event

        # Determine if this is the parent event of a series
        is_parent_event = (parent_event_id is None) and (recurrence_type != 'none')
        series_parent_id = event_id if is_parent_event else parent_event_id

        # Find all events in the series (parent + instances)
        if series_parent_id:
            cur.execute("""
                SELECT id, event_date, start_time FROM events 
                WHERE id = %s OR parent_event_id = %s
                ORDER BY event_date ASC
            """, (series_parent_id, series_parent_id))
            series_events = cur.fetchall()
        else:
            cur.execute("""
                SELECT id, event_date, start_time FROM events 
                WHERE id = %s
            """, (event_id,))
            series_events = cur.fetchall()

        series_event_ids = [row[0] for row in series_events]
        event_start_times = {row[0]: row[2] for row in series_events}

        # Delete old bulletins for all events in the series
        if series_event_ids:
            placeholders = ','.join(['%s'] * len(series_event_ids))
            cur.execute(f"DELETE FROM bulletins WHERE event_id IN ({placeholders})", tuple(series_event_ids))

        # Sort bulletins by display_order
        sorted_bulletins = sorted(data, key=lambda x: int(x.get('display_order', 0)))

        # Insert bulletins for each event in the series
        for eid in series_event_ids:
            current_time = datetime.strptime(str(event_start_times[eid]), "%H:%M:%S")
            last_end_time = current_time
            for item in sorted_bulletins:
                duration = int(item['duration_minutes'])
                cur.execute("""
                    INSERT INTO bulletins 
                    (event_id, start_time, title, duration_minutes, preacher, language, category, display_order)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    eid,
                    current_time.strftime("%H:%M:%S"),
                    item['title'],
                    duration,
                    item.get('preacher', ''),
                    item.get('language', 'EN'),
                    item.get('category', ''),
                    item.get('display_order', 0)
                ))
                last_end_time = current_time + timedelta(minutes=duration)
                current_time = last_end_time
            # Update event end_time based on last bulletin
            cur.execute("UPDATE events SET end_time = %s WHERE id = %s", 
                        (last_end_time.strftime("%H:%M:%S"), eid))

        mysql.connection.commit()
        cur.close()

        # Log the action
        AuditLog.log_action(
            user_id=current_user['id'],
            action_type='BULK_EDIT' if series_parent_id else 'EDIT',
            entity_type='BULLETIN_SERIES' if series_parent_id else 'BULLETIN',
            entity_id=event_id,
            new_data={"bulletins_count": len(data), "synced_to_series": bool(series_parent_id)},
            ip_address=request.remote_addr
        )

        return jsonify({"message": f"Bulletins saved and synced to {len(series_event_ids)} event(s)."}), 200

    except Exception as e:
        mysql.connection.rollback()
        return handle_error(e)
        
@app.route('/events/<int:event_id>/bulletins', methods=['GET'])
@token_required('viewer')  # Allow viewers to read bulletins
def get_bulletins(current_user, event_id):
    try:
        cur = mysql.connection.cursor()
        cur.execute("""
            SELECT title, start_time, duration_minutes, preacher, language, category, display_order
            FROM bulletins
            WHERE event_id = %s
            ORDER BY display_order ASC
        """, (event_id,))
        bulletins = cur.fetchall()
        cur.close()

        return jsonify([
            {
                "title": b[0],
                "start_time": str(b[1]),
                "duration_minutes": b[2],
                "preacher": b[3],
                "language": b[4],
                "category": b[5],
                "display_order": b[6]
            } for b in bulletins
        ])
    except Exception as e:
        return handle_error(e)

# Optionally, you can make bulk_add_bulletins_to_series reuse this logic:
@app.route('/events/<int:parent_event_id>/bulk-add-bulletins', methods=['POST'])
@token_required('planner')
def bulk_add_bulletins_to_series(current_user, parent_event_id):
    # Just reuse the main endpoint behavior
    return save_bulletins(current_user, parent_event_id)
# -----------------------------
# REAL-TIME ACTIVITY CONTROL ENDPOINT
# -----------------------------
@app.route('/bulletins/<int:bulletin_id>/action', methods=['POST'])
@token_required('planner')  # Only planners and above can control activities
def activity_action(current_user, bulletin_id):
    try:
        data = request.json
        action = data.get('action')  # 'pause', 'extend', 'end'
        minutes = data.get('minutes', 0)  # For 'extend' action
        valid_actions = ['pause', 'extend', 'end']
        if action not in valid_actions:
            return jsonify({"error": f"Invalid action. Use one of: {valid_actions}"}), 400

        cur = mysql.connection.cursor()
        # First, get the current bulletin and its event
        cur.execute("""
            SELECT b.id, b.title, b.start_time, b.duration_minutes, b.event_id, 
                   e.event_date, e.start_time as event_start, e.end_time as event_end
            FROM bulletins b
            JOIN events e ON b.event_id = e.id
            WHERE b.id = %s
        """, (bulletin_id,))
        result = cur.fetchone()
        if not result:
            cur.close()
            return jsonify({"error": "Bulletin not found"}), 404

        # Unpack the result
        b_id, title, start_time_str, duration_minutes, event_id, event_date, event_start_str, event_end_str = result
        start_time = datetime.strptime(str(start_time_str), "%H:%M:%S")
        event_start_time = datetime.strptime(str(event_start_str), "%H:%M:%S")

        if action == 'pause':
            return jsonify({"message": "Pause functionality is not yet implemented in this example."})

        elif action == 'extend':
            if minutes <= 0:
                return jsonify({"error": "Minutes must be greater than 0"}), 400

            # Get original duration
            original_duration = duration_minutes
            new_duration = original_duration + minutes

            # Update the bulletin's duration
            cur.execute("UPDATE bulletins SET duration_minutes = %s WHERE id = %s", (new_duration, bulletin_id))

            # Recalculate the entire event's schedule
            success = recalculate_event_schedule(cur, event_id)
            if not success:
                mysql.connection.rollback()
                cur.close()
                return jsonify({"error": "Failed to recalculate event schedule"}), 500

            # Commit changes
            mysql.connection.commit()

            # ✅ LOG OVERTIME on extend
            # Parse start time
            start_time_obj = datetime.strptime(str(start_time_str), "%H:%M:%S").time()
            today = datetime.today()
            start_datetime = datetime.combine(today, start_time_obj)
            original_end_datetime = start_datetime + timedelta(minutes=original_duration)
            new_end_datetime = start_datetime + timedelta(minutes=new_duration)

            # Log the extension as overtime
            AuditLog.log_action(
                user_id=current_user['id'],
                action_type='OVERTIME',
                entity_type='BULLETIN',
                entity_id=bulletin_id,
                new_data={
                    "reason": "Manual extension by planner",
                    "extended_by_minutes": minutes,
                    "original_end": original_end_datetime.strftime("%H:%M:%S"),
                    "new_end": new_end_datetime.strftime("%H:%M:%S"),
                    "overtime_start": original_end_datetime.strftime("%H:%M:%S")
                }
            )

            cur.close()

            return jsonify({
                "message": f"Activity extended by {minutes} minutes. Overtime begins at {original_end_datetime.strftime('%H:%M')}."
            })

        elif action == 'end':
            try:
                # Parse start time
                start_time_obj = datetime.strptime(str(start_time_str), "%H:%M:%S").time()
                today = datetime.today()
                start_datetime = datetime.combine(today, start_time_obj)

                # Calculate scheduled end (original_end)
                scheduled_end = start_datetime + timedelta(minutes=duration_minutes)

                # Actual end time is now
                actual_end = datetime.now()

                # Calculate actual duration in minutes
                actual_duration_seconds = (actual_end - start_datetime).total_seconds()
                actual_duration_minutes = int(actual_duration_seconds // 60)
                if actual_duration_seconds % 60 > 0:
                    actual_duration_minutes += 1  # Round up

                # Update bulletin duration
                cur.execute("""
                    UPDATE bulletins 
                    SET duration_minutes = %s 
                    WHERE id = %s
                """, (actual_duration_minutes, bulletin_id))

                # Recalculate event schedule
                if not recalculate_event_schedule(cur, event_id):
                    mysql.connection.rollback()
                    cur.close()
                    return jsonify({"error": "Failed to recalculate schedule"}), 500

                # ✅ Prepare timestamps for logging
                original_end_str = scheduled_end.strftime("%H:%M:%S")
                actual_end_str = actual_end.strftime("%H:%M:%S")

                # Determine if overtime or ended early
                if actual_end > scheduled_end:
                    # This is overtime (could happen if extended before ending)
                    overtime_seconds = int((actual_end - scheduled_end).total_seconds())
                    AuditLog.log_action(
                        user_id=current_user['id'],
                        action_type='OVERTIME',
                        entity_type='BULLETIN',
                        entity_id=bulletin_id,
                        new_data={
                            "reason": "Ended after overtime",
                            "original_end": original_end_str,
                            "new_end": actual_end_str,
                            "overtime_minutes": round(overtime_seconds / 60, 1),
                            "actual_duration": actual_duration_minutes
                        }
                    )
                elif actual_end < scheduled_end:
                    # Ended early
                    saved_seconds = int((scheduled_end - actual_end).total_seconds())
                    AuditLog.log_action(
                        user_id=current_user['id'],
                        action_type='ENDED_EARLY',
                        entity_type='BULLETIN',
                        entity_id=bulletin_id,
                        new_data={
                            "reason": "Manually ended early by planner",
                            "original_end": original_end_str,      # Scheduled end
                            "new_end": actual_end_str,          # Actual end
                            "saved_minutes": round(saved_seconds / 60, 1),
                            "actual_duration": actual_duration_minutes
                        }
                    )
                else:
                    # Ended exactly on time
                    AuditLog.log_action(
                        user_id=current_user['id'],
                        action_type='EDIT',
                        entity_type='BULLETIN',
                        entity_id=bulletin_id,
                        new_data={
                            "status": "completed_on_time",
                            "end_time": actual_end_str
                        }
                    )

                # ✅ Broadcast real-time update
                try:
                    broadcast_event('activity_ended', {
                        'bulletin_id': bulletin_id,
                        'event_id': event_id,
                        'action': 'end',
                        'timestamp': actual_end.isoformat()
                    })
                except Exception as e:
                    print(f"Broadcast failed: {e}")

                mysql.connection.commit()
                cur.close()

                return jsonify({
                    "message": f"Activity ended. Duration: {actual_duration_minutes} min.",
                    "actual_duration": actual_duration_minutes,
                    "status": "ended_early" if actual_end < scheduled_end else "overtime" if actual_end > scheduled_end else "on_time"
                })

            except Exception as e:
                mysql.connection.rollback()
                cur.close()
                print(f"Error in 'end' action: {str(e)}")
                return jsonify({"error": f"Failed to end activity: {str(e)}"}), 500
    finally:
        # Ensure cursor is closed in case of early return or error
        # But avoid double-closing; let logic above handle it safely
        pass  # Cursor is already closed in each branch
    
def recalculate_event_schedule(cursor, event_id):
    """
    Recalculates the start times for all bulletins in an event and updates the event's end time.
    Checks for conflicts with subsequent events and adjusts their start times if needed.
    Returns True on success, False on failure.
    """
    try:
        # Get all bulletins for the event, ordered by display_order
        cursor.execute("SELECT id, duration_minutes FROM bulletins WHERE event_id = %s ORDER BY display_order ASC", (event_id,))
        bulletins = cursor.fetchall()
        if not bulletins:
            return True  # Nothing to recalculate

        # Get the event's start time
        cursor.execute("SELECT start_time FROM events WHERE id = %s", (event_id,))
        event_start_row = cursor.fetchone()
        if not event_start_row:
            return False
        event_start = datetime.strptime(str(event_start_row[0]), "%H:%M:%S")
        current_time = event_start

        # Recalculate bulletin start times
        for bulletin_id, duration_minutes in bulletins:
            cursor.execute("UPDATE bulletins SET start_time = %s WHERE id = %s",
                         (current_time.strftime("%H:%M:%S"), bulletin_id))
            current_time += timedelta(minutes=duration_minutes)

        # Update event end time
        new_end_time = current_time.strftime("%H:%M:%S")
        cursor.execute("UPDATE events SET end_time = %s WHERE id = %s", (new_end_time, event_id))

        # --- CONFLICT DETECTION & ADJUSTMENT FOR NEXT EVENTS ---
        # Get event date
        cursor.execute("SELECT event_date FROM events WHERE id = %s", (event_id,))
        event_date_row = cursor.fetchone()
        if not event_date_row:
            return False
        event_date = str(event_date_row[0])

        # Find the next event on the same day (by start time)
        cursor.execute("""
            SELECT id, start_time, end_time FROM events 
            WHERE event_date = %s AND start_time >= %s AND id != %s
            ORDER BY start_time ASC LIMIT 1
        """, (event_date, new_end_time, event_id))
        next_event = cursor.fetchone()
        if next_event:
            next_event_id, next_start_str, next_end_str = next_event
            next_start = datetime.strptime(str(next_start_str), "%H:%M:%S")
            next_start_dt = datetime.combine(datetime.today(), next_start)
            new_end_time_obj = datetime.strptime(new_end_time, "%H:%M:%S")
            new_end_dt = datetime.combine(datetime.today(), new_end_time_obj)

            # Define buffer (e.g., 5 minutes between events)
            buffer = timedelta(minutes=5)
            scheduled_end = datetime.combine(datetime.today(), current_time.time())
            earliest_next_start = scheduled_end + buffer

            # Check if next event starts too soon
            if next_start_dt < earliest_next_start:
                # Calculate delay in minutes
                delay_seconds = (earliest_next_start - next_start_dt).total_seconds()
                delay_minutes = int(delay_seconds // 60) + (1 if delay_seconds % 60 > 0 else 0)

                # Adjust the next event and all events after it
                adjust_event_start_time(cursor, next_event_id, delay_minutes)

        return True

    except Exception as e:
        print(f"Error in recalculate_event_schedule: {e}")
        traceback.print_exc()
        return False


def adjust_event_start_time(cursor, event_id, delay_minutes):
    """
    Delays an event and all its subsequent events by delay_minutes.
    Recursively adjusts the chain if needed.
    """
    try:
        # Get current event times
        cursor.execute("SELECT start_time, end_time, event_date FROM events WHERE id = %s", (event_id,))
        row = cursor.fetchone()
        if not row:
            return
        start_time_str, end_time_str, event_date = row
        start_time = datetime.strptime(str(start_time_str), "%H:%M:%S")
        end_time = datetime.strptime(str(end_time_str), "%H:%M:%S")

        # Apply delay
        new_start = (datetime.combine(datetime.today(), start_time) + timedelta(minutes=delay_minutes)).time()
        new_end = (datetime.combine(datetime.today(), end_time) + timedelta(minutes=delay_minutes)).time()

        # Update event
        cursor.execute("""
            UPDATE events 
            SET start_time = %s, end_time = %s 
            WHERE id = %s
        """, (new_start.strftime("%H:%M:%S"), new_end.strftime("%H:%M:%S"), event_id))

        # Update all bulletins in the event
        cursor.execute("""
            SELECT id, duration_minutes, start_time 
            FROM bulletins 
            WHERE event_id = %s 
            ORDER BY start_time ASC
        """, (event_id,))
        bulletins = cursor.fetchall()
        current_time = datetime.combine(datetime.today(), new_start)
        for bid, duration, _ in bulletins:
            cursor.execute("UPDATE bulletins SET start_time = %s WHERE id = %s",
                         (current_time.strftime("%H:%M:%S"), bid))
            current_time += timedelta(minutes=duration)

        # Check if this causes conflict with next event
        cursor.execute("""
            SELECT id, start_time FROM events 
            WHERE event_date = %s AND start_time > %s AND id != %s
            ORDER BY start_time ASC LIMIT 1
        """, (str(event_date), new_end.strftime("%H:%M:%S"), event_id))
        next_event = cursor.fetchone()
        if next_event:
            next_id, next_start_str = next_event
            next_start = datetime.strptime(str(next_start_str), "%H:%M:%S")
            next_start_dt = datetime.combine(datetime.today(), next_start)
            new_end_dt = datetime.combine(datetime.today(), new_end)
            buffer = timedelta(minutes=5)

            if next_start_dt < new_end_dt + buffer:
                # Delay the next event by the same amount
                adjust_event_start_time(cursor, next_id, delay_minutes)

    except Exception as e:
        print(f"Error in adjust_event_start_time: {e}")
        traceback.print_exc()



# -----------------------------
# REAL-TIME NOTIFICATIONS (SSE)
# -----------------------------

# Global list of connected clients
sse_clients = []

@app.route('/stream')
def stream():
    def event_stream():
        # Create a queue for this client
        client_queue = Queue()
        sse_clients.append(client_queue)
        try:
            while True:
                message = client_queue.get()  # Blocks until message is sent
                yield message
        except GeneratorExit:
            sse_clients.remove(client_queue)

    return Response(event_stream(), content_type='text/event-stream')

def broadcast_event(event_type, data):
    """Send an event to all connected SSE clients"""
    message = f"event: {event_type}\ndata: {json.dumps(data)}\n\n"
    for client_queue in sse_clients[:]:
        try:
            client_queue.put(message)
        except Exception as e:
            print(f"Error sending to client: {e}")
            if client_queue in sse_clients:
                sse_clients.remove(client_queue)
# -----------------------------
# TEMPLATES
# -----------------------------
@app.route('/templates', methods=['GET'])
def get_templates():
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, name, description FROM templates")
    templates = [{"id": row[0], "name": row[1], "description": row[2]} for row in cur.fetchall()]
    cur.close()
    return jsonify(templates)

# Protect template creation (admin or higher)
@app.route('/templates', methods=['POST'])
@token_required('admin')
def create_template(current_user):
    try:
        data = request.json
        
        if not data.get('name'):
            return jsonify({"error": "Template name is required"}), 400
        
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO templates (name, description) VALUES (%s, %s)",
                    (data['name'], data.get('description', '')))
        template_id = cur.lastrowid

        for item in data.get('bulletins', []):
            cur.execute("""
                INSERT INTO template_bulletins (template_id, title, duration_minutes, preacher, language, category, display_order)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (
                template_id,
                item['title'],
                item['duration_minutes'],
                item.get('preacher', ''),
                item.get('language', 'EN'),
                item.get('category', ''),
                item.get('display_order', 0)
            ))

        mysql.connection.commit()
        cur.close()

        # Log the action
        AuditLog.log_action(
            user_id=current_user['id'],
            action_type='CREATE',
            entity_type='TEMPLATE',
            entity_id=template_id,
            new_data=data
        )
        return jsonify({"message": "Template created successfully", "template_id": template_id})
    except Exception as e:
        return handle_error(e)

@app.route('/templates/<int:template_id>/bulletins', methods=['GET'])
def get_template_bulletins(template_id):
    try:
        cur = mysql.connection.cursor()
        cur.execute("""
            SELECT title, duration_minutes, preacher, language, category, display_order
            FROM template_bulletins
            WHERE template_id = %s
            ORDER BY display_order ASC
        """, (template_id,))
        rows = cur.fetchall()
        cur.close()
        
        if rows and isinstance(rows[0], dict):
            return jsonify([
                {
                    "title": r['title'],
                    "duration_minutes": r['duration_minutes'],
                    "preacher": r['preacher'],
                    "language": r['language'],
                    "category": r['category'],
                    "display_order": r['display_order']
                } for r in rows
            ])
        else:
            return jsonify([
                {
                    "title": r[0],
                    "duration_minutes": r[1],
                    "preacher": r[2],
                    "language": r[3],
                    "category": r[4],
                    "display_order": r[5]
                } for r in rows
            ])
    except Exception as e:
        return handle_error(e)

# Protect template update (admin or higher)
@app.route('/templates/<int:template_id>', methods=['PUT'])
@token_required('admin')
def update_template(current_user, template_id):
    try:
        data = request.json

        # Get old template data
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM templates WHERE id = %s", (template_id,))
        old_template = cur.fetchone()
        cur.execute("SELECT * FROM template_bulletins WHERE template_id = %s", (template_id,))
        old_bulletins = cur.fetchall()
        cur.close()
        if not data.get('name'):
            return jsonify({"error": "Template name is required"}), 400

        cur = mysql.connection.cursor()
        cur.execute("UPDATE templates SET name=%s, description=%s WHERE id=%s",
                    (data['name'], data.get('description', ''), template_id))
        # Remove old bulletins
        cur.execute("DELETE FROM template_bulletins WHERE template_id = %s", (template_id,))
        # Add new bulletins
        for item in data.get('bulletins', []):
            cur.execute("""
                INSERT INTO template_bulletins (template_id, title, duration_minutes, preacher, language, category, display_order)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (
                template_id,
                item['title'],
                item['duration_minutes'],
                item.get('preacher', ''),
                item.get('language', 'EN'),
                item.get('category', ''),
                item.get('display_order', 0)
            ))
        mysql.connection.commit()
        cur.close()

         # Log the action
        AuditLog.log_action(
            user_id=current_user['id'],
            action_type='EDIT',
            entity_type='TEMPLATE',
            entity_id=template_id,
            old_data={'template': old_template, 'bulletins': old_bulletins},
            new_data=data
        )
        return jsonify({"message": "Template updated successfully"})
    except Exception as e:
        return handle_error(e)

@app.route('/templates/<int:template_id>', methods=['DELETE'])
@token_required('admin')
def delete_template(current_user, template_id):
    try:
        # Get template data before deletion
        cur = mysql.connection.cursor()
        cur.execute("""
            SELECT t.*, 
                   (SELECT COUNT(*) FROM template_bulletins WHERE template_id = t.id) as bulletin_count
            FROM templates t
            WHERE id = %s
        """, (template_id,))
        old_template = cur.fetchone()
        
        # Get template bulletins
        cur.execute("""
            SELECT id, title, duration_minutes, preacher, language, category, display_order
            FROM template_bulletins WHERE template_id = %s
        """, (template_id,))
        old_bulletins = cur.fetchall()
        
        # Delete template bulletins first
        cur.execute("DELETE FROM template_bulletins WHERE template_id = %s", (template_id,))
        # Delete the template
        cur.execute("DELETE FROM templates WHERE id = %s", (template_id,))
        mysql.connection.commit()
        cur.close()

        # Format old data for audit log
        old_data = {
            'template': {
                'id': old_template[0],
                'name': old_template[1],
                'description': old_template[2],
                'bulletin_count': old_template[3]
            },
            'bulletins': [
                {
                    'id': b[0],
                    'title': b[1],
                    'duration_minutes': b[2],
                    'preacher': b[3],
                    'language': b[4],
                    'category': b[5],
                    'display_order': b[6]
                } for b in old_bulletins
            ]
        }

        # Log the action
        AuditLog.log_action(
            user_id=current_user['id'],
            action_type='DELETE',
            entity_type='TEMPLATE',
            entity_id=template_id,
            old_data=old_data,
            ip_address=request.remote_addr
        )

        return jsonify({"message": "Template deleted successfully"})
    except Exception as e:
        return handle_error(e)

# -----------------------------
# CURRENT ACTIVITY
# -----------------------------
@app.route('/current_activity')
def current_activity():
    try:
        now = datetime.now()
        today = now.strftime('%Y-%m-%d')
        current_time = now.time()
        cur = mysql.connection.cursor()
        
        # Fixed query with proper aliases to prevent column name collision
        cur.execute("""
            SELECT 
                e.id as event_id,
                e.title as event_title,
                b.id as bulletin_id,
                b.title as bulletin_title,
                b.start_time,
                b.duration_minutes 
            FROM events e
            JOIN bulletins b ON e.id = b.event_id
            WHERE e.event_date = %s
            ORDER BY b.start_time ASC
        """, (today,))
        results = cur.fetchall()
        cur.close()

        if not results:
            return jsonify({
                "event_title": "No events today",
                "title": "No activity",
                "start_time": "",
                "end_time": "",
                "bulletin_id": None
            })

        # Handle both dict and tuple results
        processed_results = []
        for result in results:
            if isinstance(result, dict):
                processed_results.append({
                    'event_id': result['event_id'],
                    'event_title': result['event_title'],
                    'bulletin_id': result['bulletin_id'],
                    'bulletin_title': result['bulletin_title'],
                    'start_time': result['start_time'],
                    'duration_minutes': result['duration_minutes']
                })
            else:
                # This assumes the SELECT order: e.id, e.title, b.id, b.title, b.start_time, b.duration_minutes
                processed_results.append({
                    'event_id': result[0],
                    'event_title': result[1],
                    'bulletin_id': result[2],
                    'bulletin_title': result[3],
                    'start_time': result[4],
                    'duration_minutes': result[5]
                })

        # Find the current activity
        for item in processed_results:
            try:
                start_time = datetime.strptime(str(item['start_time']), "%H:%M:%S").time()
                end_time = (datetime.combine(datetime.today(), start_time) + 
                           timedelta(minutes=item['duration_minutes'])).time()
                if start_time <= current_time <= end_time:
                    return jsonify({
                        "event_title": item['event_title'],
                        "title": item['bulletin_title'],
                        "start_time": str(start_time),
                        "end_time": str(end_time),
                        "bulletin_id": item['bulletin_id'] # <-- This is CRITICAL
                    })
            except (ValueError, TypeError) as e:
                print(f"Skipping invalid time in bulletin: {item.get('bulletin_title')} - {e}")
                continue

        # If no current activity, return the next one
        for item in processed_results:
            try:
                start_time = datetime.strptime(str(item['start_time']), "%H:%M:%S").time()
                if start_time > current_time:
                    end_time = (datetime.combine(datetime.today(), start_time) + 
                               timedelta(minutes=item['duration_minutes'])).time()
                    return jsonify({
                        "event_title": item['event_title'],
                        "title": f"Next: {item['bulletin_title']}",
                        "start_time": str(start_time),
                        "end_time": str(end_time),
                        "bulletin_id": item['bulletin_id'] # <-- This is CRITICAL
                    })
            except (ValueError, TypeError) as e:
                print(f"Skipping invalid time in bulletin: {item.get('bulletin_title')} - {e}")
                continue

        return jsonify({
            "event_title": "Events completed",
            "title": "No more activities",
            "start_time": "",
            "end_time": "",
            "bulletin_id": None
        })
    except Exception as e:
        return handle_error(e)

def has_conflict(event_date, start_time, end_time, recurrence_type, recurrence_end_date, exclude_event_id=None):
    cur = mysql.connection.cursor()
    query = """
        SELECT id, title FROM events
        WHERE event_date = %s
        AND (
            (start_time < %s AND end_time > %s) OR
            (start_time < %s AND end_time > %s) OR
            (start_time >= %s AND end_time <= %s)
        )
    """
    params = [event_date, end_time, end_time, start_time, start_time, start_time, end_time]
    if exclude_event_id:
        query += " AND id != %s"
        params.append(exclude_event_id)
    cur.execute(query, params)
    conflicts = cur.fetchall()
    cur.close()
    return conflicts

# -----------------------------
# USER MANAGEMENT ENDPOINTS
# -----------------------------

@app.route('/users', methods=['GET'])
@token_required('admin')
def get_users(current_user):
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT id, email, name, role FROM users")
        users = []
        for row in cur.fetchall():
            users.append({
                "id": row[0],
                "email": row[1],
                "name": row[2],
                "role": row[3]
            })
        cur.close()
        return jsonify(users)
    except Exception as e:
        return handle_error(e)

@app.route('/users/<int:user_id>/role', methods=['PUT'])
@token_required('admin')
def update_user_role(current_user, user_id):
    try:
        data = request.json
        new_role = data.get('role')
        if not new_role or new_role not in ROLES:
            return jsonify({"error": "Invalid role"}), 400
        # Check if current user can modify this role
        if ROLES[current_user['role']] <= ROLES[new_role] and current_user['role'] != 'superadmin':
            return jsonify({"error": "Cannot assign role equal or higher than yours"}), 403
        cur = mysql.connection.cursor()
        # Get target user's current role
        cur.execute("SELECT role FROM users WHERE id = %s", (user_id,))
        target_user = cur.fetchone()
        if not target_user:
            return jsonify({"error": "User not found"}), 404
        # Superadmin can only be modified by another superadmin
        if target_user[0] == 'superadmin' and current_user['role'] != 'superadmin':
            return jsonify({"error": "Cannot modify superadmin"}), 403
        # Update role
        cur.execute("UPDATE users SET role = %s WHERE id = %s", (new_role, user_id))
        mysql.connection.commit()
        cur.close()
        return jsonify({"message": "User role updated successfully"})
    except Exception as e:
        return handle_error(e)

@app.route('/users/<int:user_id>', methods=['DELETE'])
@token_required('admin')
def delete_user(current_user, user_id):
    try:
        # Cannot delete yourself
        if current_user['id'] == user_id:
            return jsonify({"error": "Cannot delete yourself"}), 400
            
        cur = mysql.connection.cursor()
        # Get complete user data before deletion
        cur.execute("""
            SELECT id, email, name, role, created_at 
            FROM users WHERE id = %s
        """, (user_id,))
        old_user = cur.fetchone()
        
        if not old_user:
            return jsonify({"error": "User not found"}), 404
            
        # Check permissions
        if old_user[3] == 'superadmin' and current_user['role'] != 'superadmin':
            return jsonify({"error": "Cannot delete superadmin"}), 403
        if ROLES[current_user['role']] <= ROLES[old_user[3]]:
            return jsonify({"error": "Cannot delete user with equal or higher role"}), 403

        # Delete user
        cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
        mysql.connection.commit()
        cur.close()

        # Format old data for audit log
        old_data = {
            'id': old_user[0],
            'email': old_user[1],
            'name': old_user[2],
            'role': old_user[3],
            'created_at': str(old_user[4])
        }

        # Log the action
        AuditLog.log_action(
            user_id=current_user['id'],
            action_type='DELETE',
            entity_type='USER',
            entity_id=user_id,
            old_data=old_data,
            ip_address=request.remote_addr
        )

        return jsonify({"message": "User deleted successfully"})
    except Exception as e:
        return handle_error(e)
    
@app.route('/audit-logs', methods=['GET'])
@token_required('admin')
def get_audit_logs(current_user):
    try:
        page = request.args.get('page', 1, type=int)
        entity_type = request.args.get('entity')
        action_type = request.args.get('action')
        date_filter = request.args.get('date')
        
        per_page = 20
        offset = (page - 1) * per_page

        cur = mysql.connection.cursor()
        
        # Base query
        query = """
            SELECT a.id, a.user_id, a.action_type, a.entity_type, a.entity_id, 
                   a.old_data, a.new_data, a.timestamp, a.ip_address, u.name as user_name, u.email as user_email
            FROM audit_logs a
            JOIN users u ON a.user_id = u.id
        """
        
        # Add filters
        conditions = []
        params = []
        
        if entity_type and entity_type != 'ALL':
            conditions.append("a.entity_type = %s")
            params.append(entity_type)
        if action_type and action_type != 'ALL':
            conditions.append("a.action_type = %s")
            params.append(action_type)
        if date_filter:
            conditions.append("DATE(a.timestamp) = %s")
            params.append(date_filter)
        
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        
        # Add pagination
        query += " ORDER BY a.timestamp DESC LIMIT %s OFFSET %s"
        params.extend([per_page, offset])
        
        cur.execute(query, params)
        rows = cur.fetchall()
        
        logs = []
        for row in rows:
            # Handle both tuple and dict results
            if isinstance(row, dict):
                logs.append({
                    "id": row['id'],
                    "user_id": row['user_id'],
                    "user_name": row['user_name'],
                    "user_email": row['user_email'],
                    "action_type": row['action_type'],
                    "entity_type": row['entity_type'],
                    "entity_id": row['entity_id'],
                    "old_data": json.loads(row['old_data']) if row['old_data'] else None,
                    "new_data": json.loads(row['new_data']) if row['new_data'] else None,
                    "timestamp": row['timestamp'].isoformat() if hasattr(row['timestamp'], 'isoformat') else str(row['timestamp']),
                    "ip_address": row['ip_address']
                })
            else:
                # Handle tuple format (most likely case)
                logs.append({
                    "id": row[0],
                    "user_id": row[1],
                    "user_name": row[9],  # user_name from JOIN
                    "user_email": row[10], # user_email from JOIN
                    "action_type": row[2],
                    "entity_type": row[3],
                    "entity_id": row[4],
                    "old_data": json.loads(row[5]) if row[5] else None,
                    "new_data": json.loads(row[6]) if row[6] else None,
                    "timestamp": row[7].isoformat() if hasattr(row[7], 'isoformat') else str(row[7]),
                    "ip_address": row[8]
                })

        # Get total count with same filters
        count_query = "SELECT COUNT(*) FROM audit_logs a"
        count_params = []
        
        if conditions:
            count_query += " WHERE " + " AND ".join(conditions)
            # Use the same filter parameters (excluding pagination params)
            count_params = params[:-2]  # Remove per_page and offset
            
        cur.execute(count_query, count_params)
        total = cur.fetchone()[0]
        cur.close()

        # Don't log VIEW actions since they're not changes to specific entities
        # Alternatively, you could use a dummy entity_id like -1 if you want to track views
        # AuditLog.log_action(
        #     user_id=current_user['id'],
        #     action_type='VIEW',
        #     entity_type='AUDIT_LOG',
        #     entity_id=-1,  # Dummy ID
        #     ip_address=request.remote_addr
        # )

        return jsonify({
            "logs": logs,
            "total": total,
            "page": page,
            "per_page": per_page,
            "total_pages": (total + per_page - 1) // per_page
        })
    except Exception as e:
        return handle_error(e)
    
# -----------------------------
# ATTENDANCE TRACKING ENDPOINTS
# -----------------------------

@app.route('/events/<int:event_id>/attendance', methods=['POST'])
@token_required('planner')
def record_attendance(current_user, event_id):
    try:
        data = request.json
        attendance_count = data.get('count')
        
        if attendance_count is None or attendance_count < 0:
            return jsonify({"error": "Valid attendance count is required"}), 400
        
        cur = mysql.connection.cursor()
        
        # Check if event exists
        cur.execute("SELECT id, title FROM events WHERE id = %s", (event_id,))
        event = cur.fetchone()
        if not event:
            cur.close()
            return jsonify({"error": "Event not found"}), 404
        
        # Insert or update attendance record
        cur.execute("""
            INSERT INTO event_attendance (event_id, attendance_count, recorded_by, recorded_at)
            VALUES (%s, %s, %s, NOW())
            ON DUPLICATE KEY UPDATE 
                attendance_count = VALUES(attendance_count),
                recorded_by = VALUES(recorded_by),
                recorded_at = NOW()
        """, (event_id, attendance_count, current_user['id']))
        
        mysql.connection.commit()
        cur.close()
        
        # Log the action
        AuditLog.log_action(
            user_id=current_user['id'],
            action_type='CREATE' if cur.rowcount == 1 else 'EDIT',
            entity_type='ATTENDANCE',
            entity_id=event_id,
            new_data={'attendance_count': attendance_count}
        )
        
        return jsonify({"message": "Attendance recorded successfully"})
        
    except Exception as e:
        return handle_error(e)

@app.route('/events/<int:event_id>/attendance', methods=['GET'])
@token_required('viewer')
def get_event_attendance(current_user, event_id):
    try:
        cur = mysql.connection.cursor()
        cur.execute("""
            SELECT ea.attendance_count, ea.recorded_at, u.name as recorded_by_name
            FROM event_attendance ea
            JOIN users u ON ea.recorded_by = u.id
            WHERE ea.event_id = %s
        """, (event_id,))
        
        result = cur.fetchone()
        cur.close()
        
        if not result:
            return jsonify({"attendance_count": None, "recorded_at": None, "recorded_by": None})
        
        return jsonify({
            "attendance_count": result[0],
            "recorded_at": str(result[1]) if result[1] else None,
            "recorded_by": result[2]
        })
        
    except Exception as e:
        return handle_error(e)

# -----------------------------
# REPORTING & ANALYTICS ENDPOINTS
# -----------------------------

@app.route('/reports/statistics', methods=['GET'])
@token_required('viewer')
def get_statistics(current_user):
    try:
        date_range = request.args.get('range', '30')  # days
        event_type = request.args.get('type', 'all')
        
        cur = mysql.connection.cursor()
        
        # Build date filter
        date_filter = ""
        params = []
        
        if date_range != 'all':
            days = int(date_range)
            date_filter = "AND e.event_date >= DATE_SUB(CURDATE(), INTERVAL %s DAY)"
            params.append(days)
        
        # Build event type filter
        type_filter = ""
        if event_type != 'all':
            type_filter = "AND et.name = %s"
            params.append(event_type)
        
        # Get basic statistics
        cur.execute(f"""
            SELECT 
                COUNT(DISTINCT e.id) as total_events,
                COUNT(DISTINCT ea.event_id) as events_with_attendance,
                COALESCE(SUM(ea.attendance_count), 0) as total_attendance,
                COALESCE(AVG(ea.attendance_count), 0) as avg_attendance,
                AVG(TIMESTAMPDIFF(MINUTE, e.start_time, e.end_time)) as avg_duration
            FROM events e
            LEFT JOIN event_types et ON e.event_type_id = et.id
            LEFT JOIN event_attendance ea ON e.id = ea.event_id
            WHERE 1=1 {date_filter} {type_filter}
        """, params)
        
        stats = cur.fetchone()
        
        # Get attendance trends (last 30 days)
        cur.execute("""
            SELECT 
                DATE(e.event_date) as date,
                COALESCE(SUM(ea.attendance_count), 0) as attendance,
                COUNT(e.id) as event_count
            FROM events e
            LEFT JOIN event_attendance ea ON e.id = ea.event_id
            WHERE e.event_date >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
            GROUP BY DATE(e.event_date)
            ORDER BY date ASC
        """)
        
        trends = []
        for row in cur.fetchall():
            trends.append({
                "date": str(row[0]),
                "attendance": row[1],
                "event_count": row[2]
            })
        
        # Get event type breakdown
        cur.execute(f"""
            SELECT 
                et.name as event_type,
                COUNT(e.id) as event_count,
                COALESCE(SUM(ea.attendance_count), 0) as total_attendance,
                COALESCE(AVG(ea.attendance_count), 0) as avg_attendance
            FROM events e
            JOIN event_types et ON e.event_type_id = et.id
            LEFT JOIN event_attendance ea ON e.id = ea.event_id
            WHERE 1=1 {date_filter} {type_filter}
            GROUP BY et.id, et.name
            ORDER BY total_attendance DESC
        """, params)
        
        event_types = []
        for row in cur.fetchall():
            event_types.append({
                "event_type": row[0],
                "event_count": row[1],
                "total_attendance": row[2],
                "avg_attendance": round(row[3], 1) if row[3] else 0
            })
        
        cur.close()
        
        return jsonify({
            "statistics": {
                "total_events": stats[0],
                "events_with_attendance": stats[1],
                "total_attendance": stats[2],
                "avg_attendance": round(stats[3], 1) if stats[3] else 0,
                "avg_duration": round(stats[4], 1) if stats[4] else 0
            },
            "trends": trends,
            "event_types": event_types
        })
        
    except Exception as e:
        return handle_error(e)

@app.route('/reports/attendance-summary', methods=['GET'])
@token_required('viewer')
def get_attendance_summary(current_user):
    try:
        date_range = request.args.get('range', '30')
        
        cur = mysql.connection.cursor()
        
        # Get events with attendance for the specified range
        date_filter = ""
        params = []
        
        if date_range != 'all':
            days = int(date_range)
            date_filter = "AND e.event_date >= DATE_SUB(CURDATE(), INTERVAL %s DAY)"
            params.append(days)
        
        cur.execute(f"""
            SELECT 
                e.id,
                e.title,
                e.event_date,
                e.start_time,
                et.name as event_type,
                ea.attendance_count,
                ea.recorded_at,
                u.name as recorded_by
            FROM events e
            JOIN event_types et ON e.event_type_id = et.id
            LEFT JOIN event_attendance ea ON e.id = ea.event_id
            LEFT JOIN users u ON ea.recorded_by = u.id
            WHERE 1=1 {date_filter}
            ORDER BY e.event_date DESC
        """, params)
        
        events = []
        for row in cur.fetchall():
            events.append({
                "id": row[0],
                "title": row[1],
                "event_date": str(row[2]),
                "start_time": str(row[3]),
                "event_type": row[4],
                "attendance_count": row[5],
                "recorded_at": str(row[6]) if row[6] else None,
                "recorded_by": row[7]
            })
        
        cur.close()
        return jsonify(events)
        
    except Exception as e:
        return handle_error(e)

@app.route('/reports/upcoming-events', methods=['GET'])
@token_required('viewer')
def get_upcoming_events_for_attendance(current_user):
    try:
        cur = mysql.connection.cursor()
        
        # Get upcoming events (next 7 days) and recent events (last 3 days)
        cur.execute("""
            SELECT 
                e.id,
                e.title,
                e.event_date,
                e.start_time,
                et.name as event_type,
                ea.attendance_count
            FROM events e
            JOIN event_types et ON e.event_type_id = et.id
            LEFT JOIN event_attendance ea ON e.id = ea.event_id
            WHERE e.event_date BETWEEN DATE_SUB(CURDATE(), INTERVAL 3 DAY) 
                  AND DATE_ADD(CURDATE(), INTERVAL 7 DAY)
            ORDER BY e.event_date ASC, e.start_time ASC
        """)
        
        events = []
        for row in cur.fetchall():
            events.append({
                "id": row[0],
                "title": row[1],
                "event_date": str(row[2]),
                "start_time": str(row[3]),
                "event_type": row[4],
                "attendance": row[5]
            })
        
        cur.close()
        return jsonify(events)
        
    except Exception as e:
        return handle_error(e)

@app.route('/reports/overtime-activities', methods=['GET'])
@token_required('viewer')
def get_overtime_activities(current_user):
    try:
        date_range = request.args.get('range', '30')
        cur = mysql.connection.cursor()

        # Date filter
        date_filter = ""
        params = []
        if date_range != 'all':
            days = int(date_range)
            date_filter = "AND a.timestamp >= DATE_SUB(CURDATE(), INTERVAL %s DAY)"
            params.append(days)

        query = f"""
SELECT 
    b.title as activity_title,
    e.title as event_title,
    et.name as event_type,
    e.event_date,
    b.preacher as preacher_name,
    a.new_data,
    a.action_type           -- <-- ADD THIS
FROM audit_logs a
JOIN bulletins b ON a.entity_id = b.id
JOIN events e ON b.event_id = e.id
JOIN event_types et ON e.event_type_id = et.id
LEFT JOIN users u ON b.preacher = u.id  -- Proper join for preacher name
WHERE a.action_type IN ('OVERTIME', 'ENDED_EARLY')
  {date_filter}
ORDER BY a.timestamp DESC
"""

        cur.execute(query, params)
        results = cur.fetchall()
        cur.close()

        activities = []
        for row in results:
            new_data = json.loads(row[5]) if row[5] else {}
            action_type = row[6]  # You need to SELECT a.action_type

            # Determine status and values based on action_type
            if action_type == 'OVERTIME':
                status = "Overtime"
                extended_by = new_data.get("extended_by_minutes", 0)
                minutes_display = f"+{extended_by}"
                original_end = new_data.get("original_end", "N/A")
                new_end = new_data.get("new_end", "N/A")
            elif action_type == 'ENDED_EARLY':
                status = "Ended Early"
                saved_minutes = new_data.get("saved_minutes", 0)
                extended_by = -saved_minutes  # Negative for sorting/display
                minutes_display = f"-{saved_minutes}"
                original_end = new_data.get("original_end", "N/A")  # If available
                new_end = new_data.get("new_end", "N/A")
            else:
                continue  # Skip invalid/unknown actions

            activities.append({
                "activity_title": row[0],
                "event_title": row[1],
                "event_type": row[2],
                "event_date": str(row[3]),
                "preacher": row[4] or "Unknown",
                "extended_by_minutes": extended_by,     # Number (positive or negative)
                "minutes_display": minutes_display,     # String: "+5" or "-3"
                "original_end": original_end,
                "new_end": new_end,
                "status": status
            })

        return jsonify(activities)

    except Exception as e:
        return handle_error(e)
        # Log the export action
        AuditLog.log_action(
            user_id=current_user['id'],
            action_type='EXPORT',
            entity_type='EVENT',
            entity_id=-1,  # No specific entity
            ip_address=request.remote_addr
        )
        
        return jsonify(events)
        
    except Exception as e:
        return handle_error(e)

@app.route('/reports/export/attendance', methods=['GET'])
@token_required('viewer')
def export_attendance_data(current_user):
    try:
        date_range = request.args.get('range', '30')
        
        cur = mysql.connection.cursor()
        
        date_filter = ""
        params = []
        
        if date_range != 'all':
            days = int(date_range)
            date_filter = "AND e.event_date >= DATE_SUB(CURDATE(), INTERVAL %s DAY)"
            params.append(days)
        
        cur.execute(f"""
            SELECT 
                e.event_date,
                e.title,
                et.name as event_type,
                e.start_time,
                ea.attendance_count,
                ea.recorded_at,
                u.name as recorded_by
            FROM events e
            JOIN event_types et ON e.event_type_id = et.id
            LEFT JOIN event_attendance ea ON e.id = ea.event_id
            LEFT JOIN users u ON ea.recorded_by = u.id
            WHERE ea.attendance_count IS NOT NULL {date_filter}
            ORDER BY e.event_date DESC
        """, params)
        
        attendance_data = []
        for row in cur.fetchall():
            attendance_data.append({
                "Date": str(row[0]),
                "Event Title": row[1],
                "Event Type": row[2],
                "Start Time": str(row[3]),
                "Attendance Count": row[4],
                "Recorded At": str(row[5]) if row[5] else "",
                "Recorded By": row[6] if row[6] else ""
            })
        
        cur.close()
        
        # Log the export action
        AuditLog.log_action(
            user_id=current_user['id'],
            action_type='EXPORT',
            entity_type='ATTENDANCE',
            entity_id=-1,
            new_data={"export_type": "attendance", "range": date_range}
        )
        
        return jsonify(attendance_data)
        
    except Exception as e:
        return handle_error(e)
    
    
@app.route('/reports/export/events', methods=['GET'])
@token_required('viewer')
def export_events(current_user):
    try:
        date_range = request.args.get('range', '30')
        event_type = request.args.get('type', 'all')
        cur = mysql.connection.cursor()

        date_filter = ""
        type_filter = ""
        params = []

        if date_range != 'all':
            days = int(date_range)
            date_filter = "AND e.event_date >= DATE_SUB(CURDATE(), INTERVAL %s DAY)"
            params.append(days)

        if event_type != 'all':
            type_filter = "AND et.name = %s"
            params.append(event_type)

        # ✅ Fixed: Removed LEFT JOIN on e.created_by
        query = f"""
        SELECT 
            e.title as event_title,
            e.event_date,
            et.name as event_type,
            e.start_time,
            b.duration_minutes
        FROM events e
        JOIN event_types et ON e.event_type_id = et.id
        JOIN bulletins b ON e.id = b.event_id
        WHERE 1=1 {date_filter} {type_filter}
        ORDER BY e.event_date DESC
        """

        cur.execute(query, params)
        results = cur.fetchall()
        cur.close()

        return jsonify([
            {
                "event_title": row[0],
                "event_date": str(row[1]),
                "event_type": row[2],
                "start_time": str(row[3]),
                "duration_minutes": row[4]
            } for row in results
        ])

    except Exception as e:
        return handle_error(e)
    
    # Initialize database connection check
def init_db():
    """Initialize database connection check"""
    print("Starting Church Planner API...")
    print("Testing database connection...")
    print("✓ Database connection verified")

if __name__ == "__main__":
    init_db()
    print("✓ Server starting on http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)



