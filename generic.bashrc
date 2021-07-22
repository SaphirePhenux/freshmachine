##########################
# my generic bashrc file
##########################

# TEXT MANIPULATION
# AWK, SED, GREP, ACK, FIND
alias zg='zgrep'
alias g='grep'
alias eg='grep -E'
alias h='history'
alias zeg='zegrep'
alias ze='zegrep'
alias t='tar'
alias f='find'
alias xt='tar xfa'
alias plgrep='grep -P --color=auto'
alias pg='grep -P --color=auto'
alias zp='zgrep -P --color=auto'
alias zpg='zgrep -P --color=auto'
alias hg='history | grep'
alias heg='history | grep -E'
alias tl='tail'
alias hd='head'
function ev() { "$@" | grep -Ev ':0$'; }
# Moving Stuff
alias ..='cd ..'
alias ...='cd ../..'
alias bk='cd -'
#General Aliases
alias lll='ls -la --color | less -NIR'
alias lsd='ls --color -d */'
alias lh='ls -lha --color'
alias less='less -NIR'
alias zless='zless -NIR'
alias e='exit'
alias qks='source ~/.bashrc && . ~/.bash_aliases'
alias of='ls -t --color' #oldest to newest
alias lof='ls -lt --color' #oldest to newest w/details
alias nf='ls -tr --color' # newest to oldest
alias lnf='ls -ltr --color' #newest to oldest w/details
function listf() { alias; declare -F; }
function linelimit() { CMD="$1"; COUNT=$2; eval $CMD | awk -v charcount=$COUNT '{print substr($0,1,charcount)}'; }
alias limit='linelimit'
function readini() { awk '/'"$2"'/,!NF' $1 | awk -F"=" '/'"$3"'/ {print $2}'; }
function readini2() { awk -v section="$2" '$0~section,!NF' "$1" | awk -v entry="$3" -F"=" '$0~entry {print $2}'; }

# PROMPT STUFF
PS1='${debian_chroot:+($debian_chroot)}\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\n\$ '













