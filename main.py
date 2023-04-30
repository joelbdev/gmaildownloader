#gmail quickstart guide: https://developers.google.com/gmail/api/quickstart/python
from __future__ import print_function
import pickle
import os.path
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
import pandas as pd
import base64
from bs4 import BeautifulSoup
import argparse
from datetime import datetime
from dateutil.parser import parse
import pytz
import json
import sys
import hashlib
import logging
import warnings

'''TODO:
1. Device login and login history - if this is possible
2. Remove the repetition in each function
'''

# If modifying these scopes, delete the file token.pickle.
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly'] #read only API

def getinbox(datetimeinput, dateinput):
    '''
    Calls gmail API to export emails from the inbox up to a date specified by the argument
    :return: JSON of emails and csv of email attributes
    '''

    creds = None
    # The file token.pickle stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)

    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)  # you get this credentials JSON from registering an app with Google
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)

    service = build('gmail', 'v1', credentials=creds)

    # Call the Gmail API
    emaillist = service.users().messages().list(userId='me',
                                                q=f'before: {dateinput} label: inbox').execute()  # will list message ID to the specified date
    emails = emaillist.get('messages', [])  # this is the returned JSON with the message ID
    # df = pd.DataFrame(columns=['ID', 'From', 'Date', 'Subject', 'Body', 'Attachment ID', 'Email hash', 'Attachment hash','Full headers'])
    dictlist = ['ID', 'From', 'Date', 'Subject', 'Body', 'Attachment ID', 'Email hash', 'Attachment hash','Full headers']
    dict = {}
    for item in dictlist:
        dict[item] = []

    # dict['ID'] = []
    # dict['From'] = []
    # dict['Date'] = []
    # dict['Subject'] = []
    # dict['Body'] = []
    # dict['Attachment ID'] = []
    # dict['Email hash'] = []
    # dict['Attachment hash'] = []
    # dict['Full headers'] = []

    # iterate over the email ID
    if not emails:
        print("No emails found")

    else:
        for email in emails:  # iterate over each of the id's in the JSON

            # https://developers.google.com/gmail/api/reference/rest/v1/users.messages (What you can pull from messages)

            msg = service.users().messages().get(userId='me', id=email['id']).execute()  # get the message using the email id
            msgheaders = (msg['payload']['headers'])
            for item in msgheaders:
                if item['name'] == 'Date':
                    datelimit = item['value']
            date_object = parse(datelimit) #get the date the message was sent/recieved

            if date_object < datetimeinput:  # precludes emails after input time
                messageid = (msg['id'])
                with open(f'inbox {messageid}.txt', 'w+') as outfile:
                    json.dump(msg, outfile)
                    outfile.flush()
                    outfile.seek(0)
                    data = outfile.read()
                    h = hashlib.md5()
                    h.update(data.encode('utf-8'))
                    digest = h.hexdigest()
                    logging.info(str(datetime.now()) + f" {messageid} downloaded from inbox. Email recieved {datelimit}. Hash = {digest}")

                dict['ID'].append(messageid)
                fullheaders = (msg['payload']['headers'])
                attachmentdigest = 'No attachment'
                attachmentid = 'No attachment'

                try: #get attachment ID, if it exists, it will be here.
                    attachmentparts = (msg['payload']['parts'])
                    for item in attachmentparts:
                        if item['filename']:
                            attachmentid = item['body']['attachmentId']
                            attachment = service.users().messages().attachments().get(userId='me', messageId=msg['id'],id=attachmentid).execute()  # download attachment
                            file_data = base64.urlsafe_b64decode(attachment['data'])  # decode attachment and reencode UTF-8
                            f = open(f'{messageid} {item["filename"]}', 'wb+')
                            f.write(file_data)
                            f.flush()
                            f.seek(0)
                            date = f.read()
                            h2 = hashlib.md5()
                            h2.update(data.encode('utf-8'))
                            attachmentdigest = h.hexdigest()
                            f.close()
                            logging.info(str(datetime.now()) + f" {item['filename']} attachment downloaded from inbox.")

                except:
                    pass

                # look for Subject, Sender and Time in the headers

                for item in fullheaders:
                    if item['name'] == 'Subject':
                        subject = item['value']
                        dict['Subject'].append(subject)
                    if item['name'] == 'From':
                        sender = item['value']
                        dict['From'].append(sender)
                    if item['name'] == 'Date':
                        emaildate = item['value']
                        dict['Date'].append(emaildate)

                bodybase64 = (msg['payload']['body'])

                if bodybase64['size'] == 0:  # some of the email body is further nested within 'parts'
                    mssg_parts = (msg['payload']['parts'])  # fetching the message parts
                    part_one = mssg_parts[0]  # fetching first element of the part
                    part_body = part_one['body']  # fetching body of the message
                    if part_body['size'] == 0:
                        dict['Body'].append('Nil message body')
                    else:
                        part_data = part_body['data']  # fetching data from the body
                        cleaned = part_data.replace("-", "+").replace("_", "/")
                        decoded = base64.b64decode(bytes(cleaned, 'UTF-8'))  # decoding from Base64 to UTF-8
                        soup = BeautifulSoup(decoded, 'lxml')
                        # Catches no body error
                        try:
                            msg_body = soup.body()
                            dict['Body'].append(msg_body)
                        except:
                            dict['Body'].append('Nil message body')

                else:
                    todecode = bodybase64['data']
                    cleaned = todecode.replace("-", "+").replace("_", "/")
                    decoded = base64.b64decode(bytes(cleaned, 'UTF-8'))
                    soup = BeautifulSoup(decoded, 'lxml')
                    # Catches no body error
                    try:
                        msg_body = soup.body()
                        dict['Body'].append(msg_body)
                    except:
                        dict['Body'] = 'Nil message body'

                dict['Attachment ID'].append(attachmentid)
                dict['Email hash'].append(digest)
                dict['Attachment hash'].append(attachmentdigest)
                dict['Full headers'].append(fullheaders)

    df = pd.DataFrame.from_dict(dict, orient='index').transpose()
    df.to_csv('inboxemails.csv')  # convert the dataframe to a csv


def getsent(datetimeinput, dateinput):
    '''
    Calls gmail API to export sent emails up to a date specified by the argument
    :return: JSON of emails and csv of email attributes
    '''

    creds = None
    # The file token.pickle stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)  # you get this credentials JSON from registering an app with Google
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)

    service = build('gmail', 'v1', credentials=creds)

    # Call the Gmail API
    emaillist = service.users().messages().list(userId='me',
                                                q=f'before: {dateinput} label: sent').execute()  # will list message ID to the specified date
    emails = emaillist.get('messages', [])  # this is the returned JSON with the message ID

    dictlist = ['ID', 'To', 'Date', 'Subject', 'Body', 'Attachment ID', 'Email hash', 'Attachment hash','Full headers']
    dict = {}
    for item in dictlist:
        dict[item] = []

    # iterate over the email ID
    if not emails:
        print("No emails found")

    else:
        for email in emails:  # iterate over each of the id's in the JSON

            # https://developers.google.com/gmail/api/reference/rest/v1/users.messages (What you can pull from messages)

            msg = service.users().messages().get(userId='me',
                                                 id=email['id']).execute()  # get the message using the email id

            msgheaders = (msg['payload']['headers']) #get the date the email was recieved/sent
            for item in msgheaders:
                if item['name'] == 'Date':
                    datelimit = item['value']
            date_object = parse(datelimit)

            if date_object < datetimeinput:  # precludes emails after input time
                messageid = (msg['id'])
                with open(f'sent {messageid}.txt', 'w+') as outfile:
                    json.dump(msg, outfile)
                    outfile.flush()
                    outfile.seek(0)
                    data = outfile.read()
                    h = hashlib.md5()
                    h.update(data.encode('utf-8'))
                    digest = h.hexdigest()
                    logging.info(str(datetime.now()) + f" {messageid} downloaded from sent. Email sent {datelimit}. Hash = {digest}")


                dict['ID'].append(messageid)
                fullheaders = (msg['payload']['headers'])
                attachmentdigest = 'No attachment'
                attachmentid = 'No attachment'

                try: #get attachment ID, if it exists, it will be here.
                    attachmentparts = (msg['payload']['parts'])
                    for item in attachmentparts:
                        if item['filename']:
                            attachmentid = item['body']['attachmentId']
                            attachment = service.users().messages().attachments().get(userId='me', messageId=msg['id'],id=attachmentid).execute()  # download attachment
                            file_data = base64.urlsafe_b64decode(attachment['data'])  # decode attachment and reencode UTF-8
                            f = open(f'{messageid} {item["filename"]}', 'wb+')
                            f.write(file_data)
                            f.flush()
                            f.seek(0)
                            date = f.read()
                            h2 = hashlib.md5()
                            h2.update(data.encode('utf-8'))
                            attachmentdigest = h.hexdigest()
                            f.close()
                            logging.info(str(datetime.now()) + f" {item['filename']} attachment downloaded from sent.")

                except:
                    pass

                # look for Subject, Sender and Time in the headers
                for item in fullheaders:
                    if item['name'] == 'Subject':
                        subject = item['value']
                        dict['Subject'].append(subject)
                    if item['name'] == 'To':
                        sender = item['value']
                        dict['To'].append(sender)
                    if item['name'] == 'Date':
                        emaildate = item['value']
                        dict['Date'].append(emaildate)

                bodybase64 = (msg['payload']['body'])

                if bodybase64['size'] == 0:  # some of the email body is further nested within 'parts'
                    mssg_parts = (msg['payload']['parts'])  # fetching the message parts
                    part_one = mssg_parts[0]  # fetching first element of the part
                    part_body = part_one['body']  # fetching body of the message
                    if part_body['size'] == 0:
                        dict['Body'].append('Nil message body')
                    else:
                        part_data = part_body['data']  # fetching data from the body
                        cleaned = part_data.replace("-", "+").replace("_", "/")
                        decoded = base64.b64decode(bytes(cleaned, 'UTF-8'))  # decoding from Base64 to UTF-8
                        soup = BeautifulSoup(decoded, 'lxml')
                        # Catches no body error
                        try:
                            msg_body = soup.body()
                            dict['Body'].append(msg_body)
                        except:
                            dict['Body'].append('Nil message body')

                else:
                    todecode = bodybase64['data']
                    cleaned = todecode.replace("-", "+").replace("_", "/")
                    decoded = base64.b64decode(bytes(cleaned, 'UTF-8'))
                    soup = BeautifulSoup(decoded, 'lxml')
                    # Catches no body error
                    try:
                        msg_body = soup.body()
                        dict['Body'].append(msg_body)
                    except:
                        dict['Body'].append('Nil message body')

                dict['Attachment ID'].append(attachmentid)
                dict['Email hash'].append(digest)
                dict['Attachment hash'].append(attachmentdigest)
                dict['Full headers'].append(fullheaders)

    df = pd.DataFrame.from_dict(dict, orient='index').transpose()
    df.to_csv('sentemails.csv')  # convert the dataframe to a csv

def getdrafts(datetimeinput, dateinput):
    '''
    Calls gmail API to export draft emails up to a date specified by the argument
    :return: JSON of emails and csv of email attributes
    '''

    creds = None
    # The file token.pickle stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    if os.path.exists('token.pickle'):
        with open('token.pickle', 'rb') as token:
            creds = pickle.load(token)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)  # you get this credentials JSON from registering an app with Google
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open('token.pickle', 'wb') as token:
            pickle.dump(creds, token)

    service = build('gmail', 'v1', credentials=creds)

    # Call the Gmail API
    emaillist = service.users().messages().list(userId='me',
                                                q=f'before: {dateinput} label: drafts').execute()  # will list message ID to the specified date
    emails = emaillist.get('messages', [])  # this is the returned JSON with the message ID

    dictlist = ['ID', 'To', 'Date', 'Subject', 'Body', 'Attachment ID', 'Email hash', 'Attachment hash','Full headers']
    dict = {}
    for item in dictlist:
        dict[item] = []

    # iterate over the email ID
    if not emails:
        print("No emails found")

    else:
        for email in emails:  # iterate over each of the id's in the JSON

            # https://developers.google.com/gmail/api/reference/rest/v1/users.messages (What you can pull from messages)

            msg = service.users().messages().get(userId='me',
                                                 id=email['id']).execute()  # get the message using the email id

            msgheaders = (msg['payload']['headers']) #get the date the email was recieved/sent
            for item in msgheaders:
                if item['name'] == 'Date':
                    datelimit = item['value']
            date_object = parse(datelimit)

            if date_object < datetimeinput:  # precludes emails after input time
                messageid = (msg['id'])
                with open(f'drafts {messageid}.txt', 'w+') as outfile:
                    json.dump(msg, outfile)
                    outfile.flush()
                    outfile.seek(0)
                    data = outfile.read()
                    h = hashlib.md5()
                    h.update(data.encode('utf-8'))
                    digest = h.hexdigest()
                    logging.info(str(datetime.now()) + f" {messageid} downloaded from drafts. Email dated {datelimit}. Hash = {digest}")


                dict['ID'].append(messageid)
                fullheaders = (msg['payload']['headers'])
                attachmentdigest = 'No attachment' #This will change if there is an attachment

                try: #get attachment ID, if it exists, it will be here.
                    attachmentparts = (msg['payload']['parts'])
                    attachmentid = 'No attachment'
                    for item in attachmentparts:
                        if item['filename']:
                            attachmentid = item['body']['attachmentId']
                            attachment = service.users().messages().attachments().get(userId='me', messageId=msg['id'],id=attachmentid).execute()  # download attachment
                            file_data = base64.urlsafe_b64decode(attachment['data'])  # decode attachment and reencode UTF-8
                            f = open(f'{messageid} {item["filename"]}', 'wb+')
                            f.write(file_data)
                            f.flush()
                            f.seek(0)
                            date = f.read()
                            h2 = hashlib.md5()
                            h2.update(data.encode('utf-8'))
                            attachmentdigest = h.hexdigest()
                            f.close()
                            logging.info(str(datetime.now()) + f" {item['filename']} attachment downloaded from drafts.")

                except:
                    pass

                # look for Subject, Sender and Time in the headers
                for item in fullheaders:
                    if item['name'] == 'Subject':
                        subject = item['value']
                        dict['Subject'].append(subject)
                    if item['name'] == 'To':
                        sender = item['value']
                        dict['To'].append(sender)
                    if item['name'] == 'Date':
                        emaildate = item['value']
                        dict['Date'].append(emaildate)

                bodybase64 = (msg['payload']['body'])

                if bodybase64['size'] == 0:  # some of the email body is further nested within 'parts'
                    mssg_parts = (msg['payload']['parts'])  # fetching the message parts
                    part_one = mssg_parts[0]  # fetching first element of the part
                    part_body = part_one['body']  # fetching body of the message
                    if part_body['size'] == 0:
                        dict['Body'].append('Nil message body')
                    else:
                        part_data = part_body['data']  # fetching data from the body
                        cleaned = part_data.replace("-", "+").replace("_", "/")
                        decoded = base64.b64decode(bytes(cleaned, 'UTF-8'))  # decoding from Base64 to UTF-8
                        soup = BeautifulSoup(decoded, 'lxml')
                        # Catches no body error
                        try:
                            msg_body = soup.body()
                            dict['Body'].append(msg_body)
                        except:
                            dict['Body'].append('Nil message body')

                else:
                    todecode = bodybase64['data']
                    cleaned = todecode.replace("-", "+").replace("_", "/")
                    decoded = base64.b64decode(bytes(cleaned, 'UTF-8'))
                    soup = BeautifulSoup(decoded, 'lxml')
                    # Catches no body error
                    try:
                        msg_body = soup.body()
                        dict['Body'].append(msg_body)
                    except:
                        dict['Body'].append('Nil message body')

                dict['Attachment ID'].append(attachmentid)
                dict['Email hash'].append(digest)
                dict['Attachment hash'].append(attachmentdigest)
                dict['Full headers'].append(fullheaders)

    df = pd.DataFrame.from_dict(dict, orient='index').transpose()
    df.to_csv('draftsemails.csv')  # convert the dataframe to a csv

if __name__ == '__main__':


    #build arguments
    parser = argparse.ArgumentParser(description='Enter a date limit for emails to download')
    parser.add_argument('-date', type=lambda d: datetime.strptime(d, '%Y-%m-%d-%H:%M:%S'), help='Enter a UTC date in this format: YYYY-MM-DD-H:M:S')
    parser.add_argument('-inbox', action='store_true', help='Downloads emails from the inbox')
    parser.add_argument('-sent', action='store_true', help='Downloads emails from the sent emails')
    parser.add_argument('-drafts', action='store_true', help='Downloads emails from the draft emails')
    parser.add_argument('-all', action='store_true', help='Downloads emails from inbox, sent and draft')

    args = parser.parse_args()
    dictionaryargs = vars(args)
    dateargs = dictionaryargs.get('date')

    utc=pytz.UTC
    datetimeinput = utc.localize(dateargs) #make the object timezone aware - i.e. set to UTC time
    dateinput = datetime.date(datetimeinput) #extract just the date
    #Enter in this format: 2020-09-22 19:28:33-07:00

    #building logging
    logging.basicConfig(filename='gmaildownloader.log', level=logging.DEBUG)
    logging.getLogger('chardet.charsetprober').setLevel(logging.INFO) #set the chardet logging module to only log info and above (removes noise on language interpretation)
    logging.info(str(datetime.now()) + " Download from gmail account started")
    warnings.filterwarnings("ignore", category=UserWarning, module='bs4') #ignore BeautifulSoup is not a HTTP client warnings (it is not being used as a client)

    #log credentials
    # with open('token.pickle', 'rb') as outfile:
    #     credread = pickle.load(outfile)
        # logging.info(str(datetime.now()) + f' Logged into gmail account with the following credentials:\n {credread}')

    #call the main function
    if len(sys.argv) == 2: #if only a date is supplied, get email from all three labels
        logging.info(str(datetime.now()) + ' Starting to download from inbox')
        getinbox(datetimeinput, dateinput)
        logging.info(str(datetime.now()) + ' Finished downloading from inbox')
        logging.info(str(datetime.now()) + ' Starting to download from sent')
        getsent(datetimeinput, dateinput)
        logging.info(str(datetime.now()) + ' Finished downloading from sent')
        logging.info(str(datetime.now()) + ' Starting to download from drafts')
        getdrafts(datetimeinput, dateinput)
        logging.info(str(datetime.now()) + ' Finished downloading from drafts')
    else:
        if sys.argv[3] == '-inbox':
            logging.info(str(datetime.now()) + ' Starting to download from inbox')
            getinbox(datetimeinput, dateinput)
            logging.info(str(datetime.now()) + ' Finished downloading from inbox')
        elif sys.argv[3] == '-draft':
            logging.info(str(datetime.now()) + ' Starting to download from drafts')
            getdrafts(datetimeinput, dateinput)
            logging.info(str(datetime.now()) + ' Finished downloading from drafts')
        elif sys.argv[3] == '-sent':
            logging.info(str(datetime.now()) + ' Starting to download from sent')
            getsent(datetimeinput, dateinput)
            logging.info(str(datetime.now()) + ' Finished downloading from sent')
        elif sys.argv[3] == '-all':
            logging.info(str(datetime.now()) + ' Starting to download from inbox')
            getinbox(datetimeinput, dateinput)
            logging.info(str(datetime.now()) + ' Finished downloading from inbox')
            logging.info(str(datetime.now()) + ' Starting to download from sent')
            getsent(datetimeinput, dateinput)
            logging.info(str(datetime.now()) + ' Finished downloading from sent')
            logging.info(str(datetime.now()) + ' Starting to download from drafts')
            getdrafts(datetimeinput, dateinput)
            logging.info(str(datetime.now()) + ' Finished downloading from drafts')












