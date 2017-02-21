#!/bin/sh

RHP_MAIN_DIR="/home/rhpmain"
RHP_PROTECTED_DIR="/home/rhpprotected"


if [ "`id | grep root`" = "" ]; then
  echo ""
  echo "You need to run this script as root."
  echo ""
  exit 0
fi

if [ ! -e "./main.xml" ]; then
  echo "Can't find ./main.xml."
  exit 0
fi

if [ ! -e "./protected.xml" ]; then
  echo "Can't find ./protected.xml."
  exit 0
fi

if [ ! -e "./auth.xml" ]; then
  echo "Can't find ./auth.xml."
  exit 0
fi

if [ ! -e "./policy.xml" ]; then
  echo "Can't find ./policy.xml."
  exit 0
fi

if [ -e "${RHP_MAIN_DIR}"/config/main.xml ]; then
  mv -f "${RHP_MAIN_DIR}"/config/main.xml "${RHP_MAIN_DIR}"/config/main.xml.ng.$(date +"%Y-%m-%d-%H-%M-%S")
  echo "${RHP_MAIN_DIR}/config/main.xml was renamed."
fi

if [ -e "${RHP_PROTECTED_DIR}"/config/protected.xml ]; then
  mv -f "${RHP_PROTECTED_DIR}"/config/protected.xml "${RHP_PROTECTED_DIR}"/config/protected.xml.ng.$(date +"%Y-%m-%d-%H-%M-%S")
  echo "${RHP_PROTECTED_DIR}/config/protected.xml was renamed."
fi

if [ -e "${RHP_PROTECTED_DIR}"/config/auth.xml ]; then
  mv -f "${RHP_PROTECTED_DIR}"/config/auth.xml "${RHP_PROTECTED_DIR}"/config/auth.xml.ng.$(date +"%Y-%m-%d-%H-%M-%S")
  echo "${RHP_PROTECTED_DIR}/config/auth.xml was renamed."
fi

if [ -e "${RHP_PROTECTED_DIR}"/config/policy.xml ]; then
  mv -f "${RHP_PROTECTED_DIR}"/config/policy.xml "${RHP_PROTECTED_DIR}"/config/policy.xml.ng.$(date +"%Y-%m-%d-%H-%M-%S")
  echo "${RHP_PROTECTED_DIR}/config/policy.xml was renamed."
fi

echo "Copying default config files ..."

cp -f ./main.xml "${RHP_MAIN_DIR}"/config/main.xml
chown rhpmain:rhpenguin "${RHP_MAIN_DIR}"/config/*.xml

cp -f ./protected.xml "${RHP_PROTECTED_DIR}"/config/protected.xml
cp -f ./auth.xml "${RHP_PROTECTED_DIR}"/config/auth.xml
cp -f ./policy.xml "${RHP_PROTECTED_DIR}"/config/policy.xml
chown rhpprotected:rhpenguin "${RHP_PROTECTED_DIR}"/config/*.xml

echo "Done."


if [ -e "${RHP_PROTECTED_DIR}"/config/qcd_secret ]; then
  rm -f "${RHP_PROTECTED_DIR}"/config/qcd_secret
  echo "${RHP_PROTECTED_DIR}/config/qcd_secret was removed."
fi

if [ -e "${RHP_PROTECTED_DIR}"/config/sess_resume_key ]; then
  rm -f "${RHP_PROTECTED_DIR}"/config/sess_resume_key
  echo "${RHP_PROTECTED_DIR}/config/sess_resume_key was removed."
fi

if [ -e "${RHP_PROTECTED_DIR}"/config/sess_resume_key_old ]; then
  rm -f "${RHP_PROTECTED_DIR}"/config/sess_resume_key_old
  echo "${RHP_PROTECTED_DIR}/config/sess_resume_key_old was removed."
fi

if [ -e "${RHP_PROTECTED_DIR}"/config/sess_resume_rvk_bfltr ]; then
  rm -f "${RHP_PROTECTED_DIR}"/config/sess_resume_rvk_bfltr
  echo "${RHP_PROTECTED_DIR}/config/sess_resume_rvk_bfltr was removed."
fi

if [ -e "${RHP_PROTECTED_DIR}"/config/sess_resume_rvk_old_bfltr ]; then
  rm -f "${RHP_PROTECTED_DIR}"/config/sess_resume_rvk_old_bfltr
  echo "${RHP_PROTECTED_DIR}/config/sess_resume_rvk_old_bfltr was removed."
fi

sleep 5

echo "- ${RHP_MAIN_DIR}/config"
ls -l ${RHP_MAIN_DIR}/config
echo ""
echo ""
echo "- ${RHP_PROTECTED_DIR}/config"
ls -l ${RHP_PROTECTED_DIR}/config
echo ""

echo "Please restart Rockhopper or reboot your system."
echo ""

exit 0
    