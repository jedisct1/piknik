function pkf --description 'copy the content of a file to the piknik clipboard'
	piknik -copy < $argv[1];
end
