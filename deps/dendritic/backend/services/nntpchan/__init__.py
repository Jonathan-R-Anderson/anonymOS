"""NNTPChan (route-B, true NNTP peering) integration.

client.py   -- minimal NNTP reader over a socket (pull mode)
overchan.py -- parse an overchan/netnews article into a structured post
importer.py -- turn a parsed article into local Thread/Post/Media rows
sync.py     -- background pull loop + on-demand sync
"""
