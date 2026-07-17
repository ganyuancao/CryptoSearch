# CryptoSearch
[Tools] Search DBLP and generate CryptoBib citation key 

### How to use
1, Search for the entries in dblp
```
python3 CryptoSearch.py [title (or part of the title)]

python3 CryptoSearch.py [author name] [year]

python3 CryptoSearch.py "full_title" // this should always work
```

2, Make your selection. 

3, Get the output.

### Add to Terminal
Open `.zshrc` (or `.bashrc` depending on what you use) and put this line in it. 

```
cbs() { (cd [Directory-of-CryptoSearch] && python3 CryptoSearch.py "$@"); }
```
Note you need to change `[Directory-of-CryptoSearch]` to the actual directory. Then open Terminal and run 
```
cbs [(a part of) the title of the paper]
```

### Disclaimer
The script is modified from https://github.com/mmaker/dblp/tree/main
