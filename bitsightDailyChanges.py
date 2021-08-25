import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import datetime
import glob
import jsonpickle

changed = False
Tdate = datetime.datetime.today().strftime('%Y-%m-%d')  # Current date : YYYY-MM-DD
yesterday_date = datetime.date.today() - datetime.timedelta(days=1)  # looks like: YYYY-MM-DD

changes = "Bitsight Changes : \n"
badChanges = "Score Decreased : \n"
goodChanges = "Score Increased : \n"

path = r"C:...." # Should be the same path as the bitshightApi Path!
pathToday = path + "\\" + str(Tdate)
pathYesterday = path + "\\" + str(yesterday_date)

listOfNames = []

for filename in glob.glob(os.path.join(pathYesterday, '*.json')):
    listOfNames.append(filename[len(pathYesterday) + 1:])
for filename in listOfNames:
    with open(pathYesterday + "\\" + filename, 'r') as fy:  # open in readonly mode
        dataYesterday = jsonpickle.decode(fy.read())
    with open(pathToday + "\\" + filename, 'r') as ft:  # open in readonly mode
        dataToday = jsonpickle.decode(ft.read())
        if dataToday["Score"] != dataYesterday["Score"]:
            if dataToday["Score"] < dataYesterday["Score"] and (dataToday["Score"] - dataYesterday["Score"]) <= -\
                    20:
                changed = True
                badChanges = badChanges + dataToday["Name"] + " : " + str(dataYesterday["Score"]) + " --> " \
                             + str(dataToday["Score"]) + "\n"
            elif dataToday["Score"] > dataYesterday["Score"]:
                changed = True
                goodChanges = goodChanges + dataToday["Name"] + " : " + str(dataYesterday["Score"]) + " --> " + \
                              str(dataToday["Score"]) + "\n"
    ft.close()
    fy.close()
changes = changes + "\n" + badChanges + "\n" + goodChanges

if changed:
    with open(path + "\\" + "Change" + str(Tdate) + ".txt", 'a') as newf:
        newf.write(changes)
    newf.close()

    # The mail address and password
    sender_address = 'Insert-Your-Mail-Here@gmail.com'
    sender_pass = 'Password'
    receiver_address = 'Where-To@Send.com'

    # Setup the MIME
    message = MIMEMultipart()
    message['From'] = sender_address
    message['To'] = receiver_address
    message['Subject'] = 'BitSight Daily Changes'  # The subject line
    # The body and the attachments for the mail
    message.attach(MIMEText(changes, 'plain'))
    # Create SMTP session for sending the mail
    session = smtplib.SMTP('smtp.gmail.com', 587)  # use gmail with port
    session.starttls()  # enable security
    session.login(sender_address, sender_pass)  # login with mail_id and password
    text = message.as_string()
    session.sendmail(sender_address, receiver_address, text)
    session.quit()
    print('Mail Sent')

else:
    print("No Changes")
