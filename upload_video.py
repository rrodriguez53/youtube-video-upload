import os
import pickle

from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.http  import MediaFileUpload


VIDEO_FILE = "video.mp4"
CLIENT_SECRETS_FILE = "client_secrets.json"
# This OAuth 2.0 access scope allows an application to upload files to the
# authenticated user's YouTube channel, but doesn't allow other types of access.
YOUTUBE_UPLOAD_SCOPE = "https://www.googleapis.com/auth/youtube.upload"
YOUTUBE_API_SERVICE_NAME = "youtube"
YOUTUBE_API_VERSION = "v3"

REDIRECT_URI = 'https://www.example.com/oauth2callback'


def get_authenticated_service():
	credentials = None
	if credentials_exist():
		credentials = get_cached_credentials()
	# See https://google-auth.readthedocs.io/en/latest/reference/google.oauth2.credentials.html for Credentials object attributes
	if not credentials or not credentials.valid:
		if credentials and credentials.expired and credentials.refresh_token:
			print("refreshing token...")
			credentials.refresh()
		else:
			credentials = request_oauth2_credentials()
		cache_credentials(credentials)

	return build(YOUTUBE_API_SERVICE_NAME, YOUTUBE_API_VERSION, credentials=credentials)


def request_oauth2_credentials():
	'''
    Steps:
		1. Set authorization parameters
		2. Redirect to Google's OAuth 2.0 server
		3. Google prompts the user for consent
		4. Handle the OAuth 2.0 server response
		5. Exchange authorization code for refresh and access tokens
	'''

	# Use the client_secret.json file to identify the application requesting
	# authorization. The client ID (from that file) and access scopes are required.
	flow = Flow.from_client_secrets_file(
	    CLIENT_SECRETS_FILE,
	    scopes=[YOUTUBE_UPLOAD_SCOPE])

	# Indicate where the API server will redirect the user after the user completes
	# the authorization flow. The redirect URI is required. The value must exactly
	# match one of the authorized redirect URIs for the OAuth 2.0 client, which you
	# configured in the API Console. If this value doesn't match an authorized URI in your
	# Google API's account you will get a 'redirect_uri_mismatch' error.
	flow.redirect_uri = REDIRECT_URI

	# Generate URL for request to Google's OAuth 2.0 server.
	# Use kwargs to set optional request parameters.
	authorization_url, state = flow.authorization_url(
	    # Enable offline access so that you can refresh an access token without
	    # re-prompting the user for permission. Recommended for web server apps.
	    access_type='offline',
	    # Enable incremental authorization. Recommended as a best practice.
	    include_granted_scopes='true',
		# Prompting the user for consent is the only way to get a refresh token as part of the credentials
		prompt='consent')

	# Your application redirects the user to Google along with the list of requested permissions.
	# The user decides whether to grant the permissions to your application.
	print(authorization_url)
	authorization_response = input("Go to the above url, allow permissions and then when you get redirected to a new page, paste the url here")

	# After the web server receives the authorization code, it can begin the exchange the authorization code for an access token.
	# First verify the authoriation server response by providing the same state token to protect against XSRF
	flow = Flow.from_client_secrets_file(
	    CLIENT_SECRETS_FILE,
	    scopes=[YOUTUBE_UPLOAD_SCOPE],
		state=state)
	flow.redirect_uri = REDIRECT_URI
	# Then exchange the authorization respnse (which contains the auth code) to get the credentials
	flow.fetch_token(authorization_response=authorization_response)
	credentials = flow.credentials

	# TO-DO: We need a persistance layer to save the credentials permanently to minimize the need to go through the
	# Oauth2 process. Once we get our initial credentials we can rely on the refresh tokens from here on out.
	print("credentials are: {}".format(credentials.to_json()))
	return credentials


# The following credentials-type functions are purposely abstracted so that they can be tweaked
# whenever we switch to a better persistance data layer
def credentials_exist():
	return os.path.exists('token.pickle')


def get_cached_credentials():
	print("Using cached credentials")
	with open('token.pickle', 'rb') as token:
		return pickle.load(token)


def cache_credentials(credentials):
	print("Caching credentials...")
	with open('token.pickle', 'wb') as token:
		pickle.dump(credentials, token)


def upload_video(youtube):
	tags = None
	body = dict(
		snippet=dict(
			title='Hello world',
			description='testing video upload',
			tags=tags
		),
		status=dict(
			# Note All videos uploaded via the videos.insert endpoint from unverified API projects will be restricted to private viewing mode.
			privacyStatus='private'
		)
	)

	# Call the API's videos.insert method to create and upload the video.
	insert_request = youtube.videos().insert(
	    part=",".join(body.keys()),
	    body=body,
	    media_body=MediaFileUpload(VIDEO_FILE, chunksize=-1, resumable=True)
	  )

	print("Uploading {}".format(VIDEO_FILE))
	response = insert_request.execute()
	print(response)
	print("Upload complete")
	#resumable_upload(insert_request)


# This method implements an exponential backoff strategy to resume a
# failed upload.
# def resumable_upload(insert_request):
#   response = None
#   error = None
#   retry = 0
#   while response is None:
#     try:
#       print "Uploading file..."
#       status, response = insert_request.next_chunk()
#       if response is not None:
#         if 'id' in response:
#           print "Video id '%s' was successfully uploaded." % response['id']
#         else:
#           exit("The upload failed with an unexpected response: %s" % response)
#     except HttpError, e:
#       if e.resp.status in RETRIABLE_STATUS_CODES:
#         error = "A retriable HTTP error %d occurred:\n%s" % (e.resp.status,
#                                                              e.content)
#       else:
#         raise
#     except RETRIABLE_EXCEPTIONS, e:
#       error = "A retriable error occurred: %s" % e
#
#     if error is not None:
#       print error
#       retry += 1
#       if retry > MAX_RETRIES:
#         exit("No longer attempting to retry.")
#
#       max_sleep = 2 ** retry
#       sleep_seconds = random.random() * max_sleep
#       print "Sleeping %f seconds and then retrying..." % sleep_seconds
#       time.sleep(sleep_seconds)



def main():
	youtube = get_authenticated_service()
	#upload_video(youtube)


main()
