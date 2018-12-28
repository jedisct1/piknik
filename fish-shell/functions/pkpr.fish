function pkpr --description 'extract piknik clipboard content sent using the pkfr command'
	piknik -paste | tar xzpvf -
end
