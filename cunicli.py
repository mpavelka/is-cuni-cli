import click
import time
import pickle
import requests
import sys



LOCALHOST_BASE_URL = 'http://localhost:8085'
BASE_URL = 'https://is.cuni.cz'
PTH_HOME = '/studium/index.php'
PTH_LOGIN = '/studium/verif.php'



def store_session(path, session):
	with open(path, "wb") as f:
		pickle.dump(session, f)

def load_session(path):
	with open(path, "rb") as f:
		return pickle.loads(f.read())

def ctx_has_session_file(ctx):
	return ctx.obj['session_file'] is not None

def ctx_get_session_file(ctx):
	return ctx.obj['session_file']



@click.group()
@click.option('--session-file', help='Path to session file.')
@click.pass_context
def cli(ctx, session_file):
	ctx.obj={}
	ctx.obj['session_file'] = session_file



@cli.command()
@click.option('--username', prompt='Username', help='Login username.')
@click.option('--password', prompt='Password', hide_input=True,
			  help='Login password.')
@click.pass_context
def login(ctx, username, password):
	"""Log in user with USERNAME and PASSWORD."""

	# New session with IS CUNI
	if ctx_has_session_file(ctx):
		session = load_session(ctx_get_session_file(ctx))
	else:
		session = requests.Session()

	# Get the index page
	res = session.get(BASE_URL+PTH_HOME)

	# Get 'tstmp' and 'accode'
	from html.parser import HTMLParser
	class _HTMLParser(HTMLParser):
		def handle_starttag(self, tag, attrs):
			if tag != 'input': return
			_attrs={}
			for attr in attrs:
				_attrs[attr[0]] = attr[1]

			if (_attrs.get("name") == "accode"):
				self.accode = _attrs.get("value")
			elif (_attrs.get("name") == "tstmp"):
				self.tstmp = _attrs.get("value")
	p = _HTMLParser()
	p.feed(res.text)
	tstmp = p.tstmp
	accode = p.accode


	# Log in
	res = session.post(BASE_URL+PTH_LOGIN,
		data={
			"tstmp": tstmp,
			"accode": accode,
			"login": username,
			"heslo": password
		})
	if 'Set-Cookie' in res.headers:
		login_success = 'idc=' in res.headers['Set-Cookie'] and 'susenka=' in res.headers['Set-Cookie']
	else: login_success = False

	if login_success:
		click.echo("Successfully logged in as {}.".format(username))
		# Store session
		if ctx_has_session_file(ctx):
			store_session(ctx_get_session_file(ctx), session)
			click.echo("Session stored to {}.".format(ctx_get_session_file(ctx)))
		else:
			click.echo("[WARNING] Session not stored.")

	else:
		click.echo("[ERROR] Couldn't log in user.")
		sys.exit(1)



if __name__ == '__main__':
	cli()
