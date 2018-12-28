function pkfr --description 'send a whole directory to the piknik clipboard, as a tar archive'
	tar czpvf - $argv | piknik -copy
end
