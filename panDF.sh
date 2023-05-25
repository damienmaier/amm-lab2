#!/bin/bash

################################################################
# Author :      Blutsh                                         #
#                                                              #
# Description : This script is used to generate a "nice"       #
#               pdf from a markdown base using pandoc.         #
#                                                              #
# Notes:        Please check https://github.com/Blutsh/PanDF   #
#               for more informations                          #
################################################################

#Just color outputs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m' 
NC='\033[0m'

#Pandoc file locations
TEMPLATE_LOCATION='/.pandoc/templates/'
TEMPLATE_NAME='panda'

#Latex Added code (top of README)
CONF='./.pandoc/conf.yml'

#original markdown location
ORIGNAL_MD='./README.md'

#final pdf location
FINAL_PDF="./rapport.pdf"

#Temp environnement
TEMP_FOLDER='./tmp/'
TEMP_MD='final.md'

TODAYDATE=`date +%d-%m-%Y`
#perl -i -pe"s/date:.*/date: \"$TODAYDATE\"/" $TEMP_FOLDER$TEMP_MD



if [[ -f $CONF && -f $HOME$TEMPLATE_LOCATION$TEMPLATE_NAME.tex ]]; then
    printf "${YELLOW}Loading existing template config...${NC}\n"
    printf "${YELLOW}Creating temp files needed${NC}\n"
    mkdir $TEMP_FOLDER
    touch $TEMP_FOLDER$TEMP_MD
    printf "${YELLOW}Compiling files${NC}\n"
    cat $CONF >> $TEMP_FOLDER$TEMP_MD

    #Check wether or no a date has been set
    isInFile=$(cat $CONF | grep -c "date:")

    #if date not set -> set it to today
    if [ $isInFile -eq 0 ]; then
       #string not contained in file
       perl -i -pe 'if($. == 2) {s//date: '$TODAYDATE' \n/}' $TEMP_FOLDER$TEMP_MD
    fi

    cat $ORIGNAL_MD >> $TEMP_FOLDER$TEMP_MD
    printf "${YELLOW}Generating PDF${NC}\n"
    pandoc $TEMP_FOLDER$TEMP_MD -o $FINAL_PDF --from markdown --template $TEMPLATE_NAME.tex --listings
    printf "${YELLOW}Cleaning up env${NC}\n"
    rm -rf $TEMP_FOLDER
    printf "${GREEN}DONE !${NC}\n"
    open $FINAL_PDF

else 
    printf "${RED}template or config does not exists.... This script wont do anythin useful :(${NC}"
fi



