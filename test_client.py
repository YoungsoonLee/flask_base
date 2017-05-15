import httplib2
import urllib
from json import loads, dumps
import urllib3
import time

def main():
	url = 'http://127.0.0.1:3000/api/v1/auth'
	data = {
		'email': 'youngtip@gmail.com',
		'password': '11111'
	}
	BACKEND_HEADERS = {
		'Content-Type':'application/x-www-form-urlencoded', 
		'Accept': 'application/json'
	}

	total_time = 0

	for i in range(1,100):
		start_time = time.time()

		"""2.03
		h = httplib2.Http(".cache")
		(resp, content) = h.request(url, "POST", body=urllib.parse.urlencode(data), headers=BACKEND_HEADERS)
		# r = loads(content)
		print(content)
		"""
		
		'''2.07'''
		http = urllib3.PoolManager()
		r = http.request('POST', url, fields=data, headers={'Accept': 'application/json'})
		# r = loads(r)
		print(r)
		
		end_time = time.time()
		print('login time >> '+str(end_time - start_time))
		total_time = total_time + (end_time - start_time)

	print('result : ' + str(total_time/100) )

	"""
	url = URL(url)
	http = HTTPClient.from_url(url)
	response = http.post(url.request_uri, body=urllib.parse.urlencode(data), headers=backend_headers)
	logger.info(response)
	"""

	"""
	http = urllib3.PoolManager()
	r = http.request('POST', url, fields=data, headers={'Accept': 'application/json'})
	# r = loads(r)
	logger.info(r)
	"""

if __name__ == '__main__':
	main()
