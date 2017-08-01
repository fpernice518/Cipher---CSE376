#Outer make file, used in conjunction with the one inside /src directory
CODE_DIR = src

.PHONY: project_code

project_code:
	     @$(MAKE) -C $(CODE_DIR)
	     @ln -f src/cipher           #make a link to the executable so we can run in this directory


clean:
	  @rm cipher 
	  @$(MAKE) -C $(CODE_DIR) clean
