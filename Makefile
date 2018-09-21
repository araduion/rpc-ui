main : main.cc rpcui.h action.cc
	gcc -std=c++11 main.cc action.cc -o main -I /usr/local/include/qt4 -L /usr/local/lib/qt4 -lQtGui -lQtCore -licui18n -g 

rpcui.h: rpcui.ui
	uic rpcui.ui -o rpcui.h

action.cc : action.h
	moc action.h -o action.cc

clean:
	rm -rf rpcui.h main core.* action.cc *~
