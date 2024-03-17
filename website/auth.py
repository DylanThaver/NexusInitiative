import base64
from io import BytesIO
import io
from flask import Blueprint, render_template, request, flash, redirect, url_for, send_file
from .models import User
from .models import Student
from .models import Staff
from .models import Report
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user
auth = Blueprint('auth',__name__)

@auth.route('/login', methods=['GET','POST'])
def login():
    if request.method=='POST':
        email=request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in Successfully!', category='success')
                if user.position=='Student':
                 login_user(user, remember=True)
                 return redirect(url_for('views.home'))
                elif user.position=='Staff':
                    login_user(user, remember=True)
                    return redirect(url_for('auth.mHome'))  
            else:
                flash('Incorrect password, try again.', category='error')
        else:
            flash('Email does not exist.', category='error')

    return render_template("login.html", user=current_user)


@auth.route('/guest', methods=['GET','POST'])
def guest():
    if request.method =='POST':
        ##user stuff
        first_name=request.form.get('first_name')
        last_name=request.form.get('last_name')

            #add user to database
        new_user=User(email="guest", first_name=first_name, last_name=last_name ,password="guest", position = "Guest")
        db.session.add(new_user)
        db.session.commit()
            
        new_user2=Student(student_num="guest", first_name=first_name, last_name=last_name, user_id=new_user.id)
        db.session.add(new_user2)
        db.session.commit()
        login_user(new_user, remember=True)
        flash('Successfully logged in as a Guest', category='Success')

        if new_user.position=='Student':
            return redirect(url_for('views.home'))
        elif new_user.position=='Staff':
            return redirect(url_for('auth.mHome'))
        elif new_user.position=='Guest':
            return redirect(url_for('views.home'))

    return render_template("guest.html", user=current_user)
    
@auth.route('/logout')
@login_required
def logout():
    user = User.query.filter_by(email='guest').first()
    student = Student.query.filter_by(student_num='guest').first()
    if student:
        db.session.delete(student)
        db.session.commit()
    
    if user:
        db.session.delete(user)
        db.session.commit()
    logout_user()
    return redirect(url_for('auth.login'))

@auth.route('/mHome', methods=['GET','POST'])
@login_required
def mHome():
    if request.method =='POST':
        email=request.form.get('email')
        first_name=request.form.get('Fname')
        last_name=request.form.get('Lname')
        password1=request.form.get('password1')
        password2=request.form.get('password2')

        user2 = User.query.filter_by(email=email).first()
        if user2:
            flash('Staff account already exists', category='error')
        elif len(first_name)<4:
            flash('First Name is too short', category='error')
        elif len(last_name)<4:
            flash('Last Name is too short', category='error')
        elif password1!=password2:
            flash('Passwords don\'t match', category='error')
        elif len(password1)<7:
            flash('password is too short', category='error')
        else:
            
            new_user=User(email=email, first_name=first_name, last_name=last_name ,password=generate_password_hash(password1, method='scrypt'), position = 'Staff')
            db.session.add(new_user)
            db.session.commit()

            new_user2=Staff(first_name=first_name, last_name=last_name, user_id=new_user.id)
            db.session.add(new_user2)
            db.session.commit()
            flash('Successfully logged in as a Guest', category='Success')


    return render_template("mHome.html", user=current_user)

@auth.route('/contact')
def contact():
    return render_template("contact.html", user=current_user)


@auth.route('/staffReports', methods=['GET','POST'] )
def staffReports():
    if request.method =='POST':
        ##user stuff
        staffId=str (request.form.get('staffId'))
        campus = (request.form.get('campus'))
        details=(request.form.get('details'))
        image = (request.files['image'])
        data = image.read()
        if data:
            image_given="image attached"
        else:
            image_given="No Image attached"
        severity = (request.form.get('stars'))
        building = str (request.form.get('BCode'))
        room = str (request.form.get('RNumber'))
        details= building+" "+room+" "+details
        inCharge=request.form.get('inCharge')

        if len(staffId)>3:
            flash('Invalid staff id', category='error')
        elif len(campus)<1:
            flash('Please enter a valid campus', category='error')
        elif len(details)<2:
            flash('Please enter extra details', category='error')
        elif len(severity)<2:
            flash('Please enter the severity', category='error')
        else:
            #add user to database
            new_user=Report(sNum=staffId, campus=campus, details=details, image_given=image_given, image=data, severity=severity, progress="No-progress", user_id=current_user.id, staff=inCharge)
            db.session.add(new_user)
            db.session.commit()
            flash('Report submitted!', category='Success')
    return render_template("staffReports.html", user=current_user)


@auth.route('/map')
def map():
    return render_template("CampusMaps.html", user=current_user)

@auth.route('/sViewReports')
def sViewReports():
    all_users = Report.query.all()
    return render_template("sViewReports.html", user=current_user, all_users=all_users)

@auth.route('/studentView', methods = ['GET'])
def studentView():
    all_users = Student.query.all()
    return render_template("studentView.html", user=current_user, all_users=all_users)


@auth.route('/viewReports', methods=['GET','POST'])
def viewReports():
    if request.method=='POST':
        severity=request.form.get('FilterSeverity')
        progress=request.form.get('progress')
        if severity=='all' and progress=='all':
            all_users = Report.query.all()
        elif severity=='all':
            all_users = Report.query.filter_by(progress=progress)
        elif progress=='all':
            all_users = Report.query.filter_by(severity=severity)
        else:
            all_users = Report.query.filter_by(severity=severity, progress=progress)
    
    else:   
        all_users = Report.query.all()
    return render_template("reportView.html", user=current_user, all_users=all_users)

@auth.route('/mainview')
def mainview():
    all_users = Staff.query.all()
    return render_template("maintenance.html", user=current_user, all_users=all_users)

@auth.route('/<int:id>/image', methods=['GET','POST'])
def serveimage(id):

    report = Report.query.get_or_404(id)
    if report.image_given=="image attached":
        return send_file(io.BytesIO(report.image), mimetype='image/jpeg')
    else:
        flash("No image was attached to the report")    
        return(render_template('edit.html', user=current_user, report=report))

@auth.route('/<int:id>/edit', methods=['GET','POST'])
def edit(id):   
    report = Report.query.filter_by(id=id).first()
    if request.method=='POST':
        studentNumber=report.sNum
        campus = (request.form.get('campus'))
        details=(request.form.get('details'))
        image = report.image
        image_given= report.image_given
        user_id=report.user_id
        severity = (request.form.get('stars'))
        progress = (request.form.get('progress'))
        staff= (request.form.get('inCharge'))

        db.session.delete(report)
        db.session.commit
        new_report=Report(id=id, sNum=studentNumber, campus=campus, details=details, image_given=image_given, image=image, severity=severity,staff=staff, progress=progress, user_id=user_id)
        db.session.add(new_report)
        db.session.commit()
        flash('Report successfully updated', category='Success')
    return render_template("edit.html", user=current_user, report=report)

@auth.route('/<int:id>/delete', methods=['GET','POST'])
def delete(id):
    staff = Staff.query.filter_by(id=id).first()
    user = User.query.filter_by(id=staff.user_id).first()
    if staff:
        db.session.delete(staff)
        db.session.commit()
    if user:
        db.session.delete(user)
        db.session.commit()

    all_users = Staff.query.all()
    return render_template("maintenance.html", user=current_user, all_users=all_users)
 
@auth.route('/<id>/delete1', methods=['GET','POST'])
def delete1(id):
    student = Student.query.filter_by(student_num=id).first()
    user = User.query.filter_by(id=student.user_id).first()
    if student:
        db.session.delete(student)
        db.session.commit()
    if user:
        db.session.delete(user)
        db.session.commit()

@auth.route('/<id>/delete2', methods=['GET','POST'])
def delete2(id):
    report = Report.query.filter_by(id=id).first()
    if report:
        db.session.delete(report)
        db.session.commit()

    all_users = report.query.all()
    return render_template("reportView.html", user=current_user, all_users=all_users)

def render_picture(data):
    render_pic=base64.b64encode(data).decode('ascii')
    return render_pic

@auth.route('/report', methods=['GET','POST'])
def report():
    
    if request.method =='POST':
        ##user stuff
        if current_user.email=='guest':
            studentNumber='guest'
        else:    
            studentNumber=str (request.form.get('sNum'))
        
        campus = (request.form.get('campus'))
        details=(request.form.get('details'))
        image = (request.files['image'])
        data = image.read()
        if data:
            image_given="image attached"
        else:
            image_given="No Image attached"
        severity = (request.form.get('stars'))
        building = str (request.form.get('BCode'))
        room = str (request.form.get('RNumber'))
        details= building+" "+room+" "+details

        if len(studentNumber)==9:
            flash('invalid student number', category='error')
        elif len(campus)<1:
            flash('Please enter a valid campus', category='error')
        elif len(details)<2:
            flash('Please enter a extra details', category='error')
        else:
            #add user to database
            new_user=Report(sNum=studentNumber, campus=campus, details=details, image_given=image_given, image=data, severity=severity, progress="No-progress", user_id=current_user.id)
            db.session.add(new_user)
            db.session.commit()
            flash('Report successfully created!', category='Success')
    if current_user.email=='guest':
        return render_template("guestReport.html", user=current_user)
    else:
        return render_template("studentreport.html", user=current_user)

@auth.route('/sign-up', methods=['GET','POST'])
def sign_up():
    if request.method =='POST':
        ##user stuff
        studentNumber=str (request.form.get('StudentNumber'))
        email=request.form.get('email')
        first_name=request.form.get('Fname')
        lastName=request.form.get('Lname')
        password1=request.form.get('password1')
        password2=request.form.get('password2')
        

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists.', category='error')
        elif len(studentNumber)==9:
            flash('invalid student number', category='error')
        elif len(email)<4:
            flash('Email is too short', category='error')
        elif len(first_name)<2:
            flash('First Name is too short', category='error')
        elif len(lastName)<2:
            flash('invalid is too short', category='error')
        elif password1!=password2:
            flash('Passwords don\'t match', category='error')
        elif len(password1)<7:
            flash('password is too short', category='error')
        
        
        else:
            #add user to database
            new_user=User(email=email, first_name=first_name, last_name=lastName ,password=generate_password_hash(password1, method='scrypt'), position = 'Student')
            db.session.add(new_user)
            db.session.commit()
            
            new_user2=Student(student_num=studentNumber, first_name=first_name, last_name=lastName, user_id=new_user.id)
            db.session.add(new_user2)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('Account created an logged in successfully!', category='Success')

            if new_user.position=='Student':
                return redirect(url_for('views.home'))
            elif new_user.position=='Staff':
                return redirect(url_for('auth.mHome'))
    
    return render_template("sign_up.html", user=current_user)
