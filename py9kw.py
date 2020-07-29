#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
#    py9kw.py - A API for the Captcha-solvingservice 9kw.eu
#
#    Copyright (C) 2014 by Jan Helbling <jan.helbling@mailbox.org>
#    Updted 2020-01-25 by over_nine_thousand
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import binascii
import json
import re
import time
import urllib.request
import validators
from base64 import b64encode, b64decode
from os import getenv
from urllib.parse import urlencode
from enum import Enum


class CaptchaFeedback(Enum):
    CAPTCHA_CORRECT = 1
    CAPTCHA_INCORRECT = 2
    CAPTCHA_ABORT_CURRENT_CAPTCHA = 3


def printInfo(msg):
    print('[py9kw] %s' % msg)


# See API docs: https://www.9kw.eu/api.html
API_BASE = 'https://www.9kw.eu/index.cgi'
# Parameter used as 'source' in all API requests
API_SOURCE = 'py9kw-api'
# Values according to website 2020-01-25
PARAM_MAX_PRIO = 20
# -1 or 0 = do not send 'prio' parameter at all.
PARAM_DEFAULT_PRIO = -1
PARAM_MIN_MAXTIMEOUT = 60
PARAM_MAX_MAXTIMEOUT = 3999
PARAM_MIN_CREDITS_TO_SOLVE_ONE_CAPTCHA = 10


class Py9kw:

    def __init__(self, apikey, env_proxy=False):
        """Initialize py9kw with APIKEY
        Verbose mode will print each step to stdout."""
        logger_prefix = '[init] '
        self.verbose = False
        self.prio = PARAM_DEFAULT_PRIO
        self.maxtimeout = PARAM_MIN_MAXTIMEOUT
        self.apikey = apikey
        self.captchaid = -1
        self.credits = -1
        self.waitSecondsPerLoop = 10
        self.extrauploaddata = {}
        # Custom errors also possible besides known API errorcodes e.g. 600 --> "ERROR_NO_USER" --> See README.md
        self.errorcode = -1
        self.sleepOutputFrequencySeconds = 3
        self.errormsg = None
        self.response = {}
        if env_proxy:
            self.proxy = getenv('http_proxy')
            if self.proxy is None:
                self.proxyhdl = urllib.request.ProxyHandler({})
                if self.verbose:
                    printInfo(logger_prefix + "Warning: You have set env_proxy=True, but http_proxy is not set!")
                    printInfo(logger_prefix + "I will countine without a Proxy.")
            else:
                self.proxyhdl = urllib.request.ProxyHandler({'http', self.proxy})
                if self.verbose:
                    printInfo(logger_prefix + "Loaded http_proxy => {}".format(self.proxy))
        else:
            self.proxyhdl = urllib.request.ProxyHandler({})
        self.opener = urllib.request.build_opener(self.proxyhdl)
        self.opener.add_headers = [('User-Agent', 'Python-urllib/3.x (py9kw-api)')]
        urllib.request.install_opener(self.opener)
        if self.verbose:
            printInfo(logger_prefix + 'Current cost for one captcha: %d' % self.getCaptchaCost())

    def resetSolver(self):
        """ Call this to reset all runtime values if you e.g. want to re-use a previously created solver instance while keeping your settings (prio, maxtimeout and so on).  """
        self.captchaid = -1
        return

    def setVerbose(self, verbose):
        self.verbose = verbose

    def setResponse(self, response):
        self.response = response

    def getResponse(self):
        return self.response

    # Checks for errors in json response and returns error_code(int) and error_message(String) separated as API returns them both in one String.
    def checkError(self, response):
        error_plain = response.get('error', None)
        if error_plain is not None:
            # Error found
            if self.verbose:
                printInfo('[checkError] Found error: Plain error: %s' % error_plain)
            try:
                error_MatchObject = re.compile(r'^(\d{4}) (.+)').search(error_plain)
                self.errorcode = int(error_MatchObject.group(1))
                self.errormsg = error_MatchObject.group(2)
                if self.verbose:
                    printInfo('[checkError] Found error: Number: %d | Message: %s' % (self.errorcode, self.errormsg))
            except:
                # This should never happen
                self.errormsg = 'Error while parsing error number and message'
                self.errorcode = 666
                printInfo(self.errormsg)
        else:
            # No error found
            if self.verbose:
                printInfo('[checkError] OK - NO ERROR')
            # Reset error state
            self.errorcode = -1
            self.errormsg = None
        return self.errorcode, self.errormsg

    def getCaptchaCost(self) -> int:
        """Returns how much credits it would cost to solve one captcha with current settings."""
        captcha_cost = PARAM_MIN_CREDITS_TO_SOLVE_ONE_CAPTCHA
        if self.getPrio() > 0:
            captcha_cost += self.getPrio()
        return captcha_cost

    def setPriority(self, prio):
        self.prio = prio

    def getPrio(self) -> int:
        if self.prio > PARAM_MAX_PRIO:
            # Fallback
            return PARAM_MAX_PRIO
        else:
            return self.prio

    def setWaitSecondsPerLoop(self, waitSeconds):
        self.waitSecondsPerLoop = waitSeconds
        return

    def getWaitSecondsPerLoop(self) -> int:
        if self.waitSecondsPerLoop > 0:
            return self.waitSecondsPerLoop
        else:
            # Fallback
            return 10

    def setAdditionalCaptchaUploadParams(self, uploaddata):
        """ Use this to add extra captcha upload parameters such as: 'case-sensitive':'1'. Be sure to always use Strings! """
        self.extrauploaddata = uploaddata

    def setTimeout(self, maxtimeout):
        self.maxtimeout = maxtimeout

    def setSleepOutputFrequency(self, outputSeconds):
        """ Defines output frequency for all loops containing sleep statements. Higher = Less output / less "comsole-spam". """
        self.sleepOutputFrequencySeconds = outputSeconds

    def getTimeout(self) -> int:
        if self.maxtimeout < PARAM_MIN_MAXTIMEOUT:
            return PARAM_MIN_MAXTIMEOUT
        elif self.maxtimeout > PARAM_MAX_MAXTIMEOUT:
            return PARAM_MAX_MAXTIMEOUT
        else:
            return self.maxtimeout

    def getCaptchaID(self) -> int:
        return self.captchaid

    def getCaptchaImageFromWebsite(self, image_url, image_path=None):
        """ Returns (captcha) image file obtained from website. And optionally saves it to <image_path>. """
        imagefile = None
        try:
            imagefile = urllib.request.urlopen(image_url).read()
            # Save file only if path is given
            if image_path is not None:
                with open(image_path, 'wb') as file:
                    file.write(imagefile)
                file.close()

            if self.verbose:
                printInfo('[getCaptchaImageFromWebsite] [OK]')
        except IOError:
            printInfo('[getCaptchaImageFromWebsite] [FAIL]')
            self.errorcode = 603
            self.errormsg = 'CAPTCHA_DOWNLOAD_FAILURE'
        return imagefile

    def uploadcaptcha(self, imagedata, store_image_path=None, maxtimeout=None, prio=None) -> int:
        """Upload the Captcha to 9kw.eu (gif/jpg/png)."""
        logger_prefix = '[uploadcaptcha] '
        # Step 1: Set optional parameters and check if user has enough credits
        if self.verbose:
            printInfo(logger_prefix + 'Attempting to upload captcha...')
        if maxtimeout is not None:
            self.setTimeout(maxtimeout)
        if prio is not None:
            self.setPriority(prio)
        if self.credits < self.getCaptchaCost():
            printInfo(logger_prefix + 'Not enough credits to solve a captcha')
            return -1
        # Step 2: Prepare image data we want to upload
        # First check if we have an URL --> Download image first
        if isinstance(imagedata, str) and validators.url(imagedata):
            if self.verbose:
                printInfo(logger_prefix + 'Provided source is an URL: %s' % imagedata)
            imagedata = self.getCaptchaImageFromWebsite(imagedata, store_image_path)
            if self.errorcode > -1:
                # Error during picture download
                print(logger_prefix + 'Error during picture download')
                return self.captchaid
        try:
            if self.verbose:
                printInfo(logger_prefix + 'Check if the imagedata is already base64 encoded...')
            if b64encode(b64decode(imagedata)) == imagedata:
                if self.verbose:
                    printInfo(logger_prefix + 'YES, already encoded')
                imagedata = imagedata
            else:
                if self.verbose:
                    printInfo(logger_prefix + 'NO, encoding it now')
                imagedata = b64encode(imagedata)
        except binascii.Error:
            imagedata = b64encode(imagedata)
        # Step 3: Prepare all other parameters we want to send
        getdata = {
            'action': 'usercaptchaupload',
            'apikey': self.apikey,
            'file-upload-01': imagedata,
            'base64': 1,
            'maxtimeout': str(self.getTimeout()),
            'source': API_SOURCE,
            'json': 1
            # 'selfsolve' : '1',	# For debugging, it's faster.
            # 'nomd5' : '1'		# always send a new imageid
        }
        currentPrio = self.getPrio()
        if currentPrio > 0:
            prio_str = str(currentPrio)
            getdata['prio'] = currentPrio
            if self.verbose:
                printInfo(logger_prefix + 'Uploading captcha with prio %d' % currentPrio)
        else:
            prio_str = 'None'
            if self.verbose:
                printInfo(logger_prefix + 'Uploading captcha without prio')
        if self.extrauploaddata is not None and len(self.extrauploaddata) > 0:
            getdata.update(self.extrauploaddata)
            if self.verbose:
                printInfo(logger_prefix + 'extra params:')
                printInfo(logger_prefix + json.dumps(self.extrauploaddata, indent=4))

        # Step 4: Send data and return captchaid
        if self.verbose:
            printInfo(logger_prefix + 'Priority: %s of %d, Maxtimeout: %d' % (prio_str, PARAM_MAX_PRIO, self.maxtimeout))
            printInfo(logger_prefix + 'Upload %d bytes to 9kw.eu...' % len(imagedata))
        json_plain = urllib.request.urlopen('%s?%s' % (API_BASE, urlencode(getdata))).read().decode('utf-8', 'ignore')
        if self.verbose:
            printInfo(logger_prefix + 'json debug: ' + json_plain)
        response = json.loads(json_plain)
        self.checkError(response)
        self.captchaid = int(response.get('captchaid', -1))
        if self.errorcode > -1 or self.captchaid == -1:
            printInfo(logger_prefix + 'Error ...')
            return -1
        if self.verbose:
            printInfo(logger_prefix + '[DONE]')
        if self.verbose:
            printInfo(logger_prefix + 'Uploaded => captchaid: %d' % self.captchaid)
        return self.captchaid

    def sleepAndGetResult(self) -> str:
        """Wait until the Captcha is solved and return result."""
        logger_prefix = '[sleepAndGetResult] '
        waitSecondsPerLoop = self.getWaitSecondsPerLoop()
        if self.verbose:
            printInfo(logger_prefix + 'Waiting until the Captcha is solved or maxtimeout %d (includes %d extra seconds) has expired ...' % (self.getTimeout(), waitSecondsPerLoop))
        if self.captchaid == -1:
            print(logger_prefix + 'WARNING: No captchaid given - no way to get a result!')
        total_time_waited = 0
        waitSecondsLeft = self.getTimeout()
        lastOutputSecondsAgo = self.sleepOutputFrequencySeconds
        while waitSecondsLeft > 0:
            if lastOutputSecondsAgo >= self.sleepOutputFrequencySeconds:
                printInfo(logger_prefix + 'Waiting for result | Seconds left: %d / %d' % (waitSecondsLeft, self.getTimeout()))
                lastOutputSecondsAgo = 0
            captchaResult = self.getresult()
            server_says_try_again = self.getResponse().get('try_again', False)
            if captchaResult is not None:
                # We've reached our goal :)
                printInfo(logger_prefix + 'Total seconds waited for result: %d' % total_time_waited)
                return captchaResult
            if self.errorcode > -1 and self.errorcode != 602:
                # Retry only on 602 NO_ANSWER_YET - step out of loop if any other error happens
                printInfo(logger_prefix + 'Error happened --> Giving up')
                break
            elif server_says_try_again == 0:
                printInfo(logger_prefix + 'Server does not want us to try again --> Stopping')
                break
            if waitSecondsLeft >= waitSecondsPerLoop:
                thisSecondsWait = waitSecondsPerLoop
            else:
                thisSecondsWait = waitSecondsLeft
            if self.verbose:
                printInfo(logger_prefix + 'Waiting %d seconds' % thisSecondsWait)
            time.sleep(thisSecondsWait)
            total_time_waited += thisSecondsWait
            waitSecondsLeft -= thisSecondsWait
            lastOutputSecondsAgo += thisSecondsWait
        printInfo(logger_prefix + 'Time expired! Failed to find result!')
        self.errorcode = 601
        self.errormsg = 'ERROR_INTERNAL_TIMEOUT'
        return None

    def getresult(self) -> str:  # https://stackoverflow.com/questions/42127461/pycharm-function-doesnt-return-anything
        """Get result from 9kw.eu. Use sleepAndGetResult for auto-wait handling! """
        logger_prefix = '[getresult] '
        getdata = {
            'action': 'usercaptchacorrectdata',
            'id': self.captchaid,
            'apikey': self.apikey,
            'info': 1,
            'source': API_SOURCE,
            'json': 1
        }
        if self.verbose:
            printInfo(logger_prefix + 'Try to fetch the solved result from 9kw.eu...')
        plain_json = urllib.request.urlopen('%s?%s' % (API_BASE, urlencode(getdata))).read().decode('utf-8', 'ignore')
        if self.verbose:
            printInfo(plain_json)
        response = json.loads(plain_json)
        self.setResponse(response)
        self.checkError(response)
        answer = response.get('answer', None)
        nodata = response.get('nodata', -1)
        thiscredits = response.get('credits', -1)
        if thiscredits != -1:
            # 2020-02-06: API might sometimes return this as a String although it is supposed to be a number
            if isinstance(thiscredits, str):
                thiscredits = int(thiscredits)
            # Update credits value on change
            if self.verbose and thiscredits != self.credits:
                print(logger_prefix + 'Updated credits value from old: %d to new: %d' % (self.credits, thiscredits))
                self.credits = thiscredits
        if nodata == 1:
            if self.verbose:
                printInfo(logger_prefix + 'No answer yet')
            self.setErrorCode(602)
            self.errormsg = 'NO_ANSWER_YET'
            return None
        elif answer is not None and answer == 'ERROR NO USER':
            # Special: We need to set an error to make sure that our sleep handling would stop!
            self.setErrorCode(600)
            self.errormsg = 'ERROR_NO_USER'
            printInfo(logger_prefix + 'No users there to solve at this moment --> Or your timeout is too small OR you\'ve aborted this captcha before')
            return None
        elif self.errorcode > -1:
            printInfo(logger_prefix + 'Error %d: %s' % (self.errorcode, self.errormsg))
            return None
        elif answer is None:
            # Answer is not given but also we did not get any errormessage
            if self.verbose:
                printInfo(logger_prefix + '[FAILURE] --> Failed to find answer --> Unknown failure')
        else:
            # Answer is given
            if self.verbose:
                printInfo(logger_prefix + '[SUCCESS]')
                printInfo(logger_prefix + 'Captcha solved! captchaid %d --> Answer: \'%s\'' % (self.captchaid, answer))
        return answer

    def setCaptchaCorrect(self, iscorrect) -> bool:
        """Send feedback, is the Captcha result correct or not?"""
        logger_prefix = '[captcha_correct] '
        if iscorrect:
            if self.verbose:
                printInfo(logger_prefix + 'Sending POSITIVE captcha solved feedback ...')
            return self.sendCaptchaFeedback(CaptchaFeedback.CAPTCHA_CORRECT.value)
        else:
            if self.verbose:
                printInfo(logger_prefix + 'Sending NEGATIVE captcha solved feedback ...')
            return self.sendCaptchaFeedback(CaptchaFeedback.CAPTCHA_INCORRECT.value)

    def abortCaptcha(self) -> bool:
        """Send feedback, aborts the already sent captcha. If no answer is available yet, no credits will be used in this case!"""
        return self.sendCaptchaFeedback(CaptchaFeedback.CAPTCHA_ABORT_CURRENT_CAPTCHA.value)

    def sendCaptchaFeedback(self, captchaFeedbackNumber) -> bool:
        """Send feedback, is the Captcha result correct(=1) or not(=2) or does the user want to abort(=3)?"""
        logger_prefix = '[sendCaptchaFeedback] '
        if self.verbose:
            printInfo(logger_prefix + 'Sending captcha feedback : %d' % captchaFeedbackNumber)
        if self.captchaid is None or self.captchaid <= 0:
            # This should only happen on wrong usage
            printInfo(logger_prefix + 'Cannot send captcha feedback because captchaid is not given')
            return False
        getdata = {
            'action': 'usercaptchacorrectback',
            'correct': captchaFeedbackNumber,
            'id': self.captchaid,
            'apikey': self.apikey,
            'source': API_SOURCE,
            'json': 1
        }
        try:
            response = json.loads(
                urllib.request.urlopen('%s?%s' % (API_BASE, urlencode(getdata))).read().decode('utf-8', 'ignore'))
            # Check for errors but do not handle them. If something does wrong here it is not so important!
            self.checkError(response)
        except:
            printInfo(logger_prefix + 'Error in captcha_correct')
            return False
        return True

    def getcredits(self):
        """Get aviable Credits..."""
        logger_info = '[getcredits] '
        if self.verbose:
            printInfo(logger_info + 'Get available Credits...')
        getdata = {
            'action': 'usercaptchaguthaben',
            'apikey': self.apikey,
            'source': API_SOURCE,
            'json': 1
        }

        response = json.loads(
            urllib.request.urlopen('%s?%s' % (API_BASE, urlencode(getdata))).read().decode('utf-8', 'ignore'))
        self.checkError(response)
        if self.errorcode > -1:
            printInfo(logger_info + 'Error: %s' % self.errormsg)
            return -1
        usercredits = response.get('credits', -1)
        if self.verbose:
            cost_per_captcha = self.getCaptchaCost()
            printInfo(logger_info + '%d credits available | Cost per captcha (with current prio %d): %d | Enough to solve approximately %d captchas' % (
                usercredits, self.getPrio(), cost_per_captcha, (usercredits / cost_per_captcha)))
        self.credits = usercredits
        return self.credits

    def setErrorCode(self, errorcode):
        self.errorcode = errorcode

    def getErrorCode(self) -> int:
        return self.errorcode


if __name__ == '__main__':
    from sys import argv

    if len(argv) != 3:
        printInfo('Forgot start-param??')
        printInfo('Usage:' + argv[0] + '<APIKEY> <TIME TO SOLVE>')
        exit(0)

    # Define exactly what we expect as a result according to: https://www.9kw.eu/api.html#apisubmit-tab
    selfsolve = True
    additionalParams = {'numeric': 1, 'min_len': 7, 'max_len': 7}
    if selfsolve:
        additionalParams['selfsolve'] = 1
        additionalParams['selfonly'] = 1
        # additionalParams['nomd5'] = 1
    captchaSolver = Py9kw(argv[1], True)
    captchaSolver.setVerbose(False)
    captchaSolver.setAdditionalCaptchaUploadParams(additionalParams)
    captchaSolver.setWaitSecondsPerLoop(5)
    captchaSolver.setTimeout(80)
    captchaSolver.setSleepOutputFrequency(10)
    # Get a Sample-Captcha
    sample_captcha_url = 'https://confluence.atlassian.com/download/attachments/216957808/captcha.png?version=1&modificationDate=1272411042125&api=v2'
    test_image_data = captchaSolver.getCaptchaImageFromWebsite(sample_captcha_url)
    if captchaSolver.getErrorCode() > -1:
        print('[py9kw-test] Captcha download failure')
        exit(1)

    creditsBefore = captchaSolver.getcredits()
    if creditsBefore < PARAM_MIN_CREDITS_TO_SOLVE_ONE_CAPTCHA:
        print('[py9kw-test] Not enough Credits! < %d' % PARAM_MIN_CREDITS_TO_SOLVE_ONE_CAPTCHA)
        exit(0)
    print('[py9kw-test] Credits: {}'.format(creditsBefore))

    # Upload it
    try:
        test_captchaid = captchaSolver.uploadcaptcha(test_image_data, True, int(argv[2]), 10)
    except IOError as e:
        print('[py9kw-test] Error while uploading the Captcha!')
        if hasattr(e, 'args'):
            print('[py9kw-test]', e.args[0])
        else:
            print('[py9kw-test]', e.filename, ':', e.strerror, '.')
        exit(1)
    # Use this switch to test captcha abort --> Should not waste any credits
    abortCaptcha = False
    if abortCaptcha:
        print('Trying to abort already uploaded captcha --> No credits should be used')
        captchaAborted = captchaSolver.abortCaptcha()
        if captchaAborted:
            print('Successfully aborted captcha')
        else:
            # This should never happen
            print('Failed to abort captcha')
        captchaSolver.getresult()
        exit(0)
    # Sleep and get result
    result = captchaSolver.sleepAndGetResult()
    # Evaluate Result
    if result is None:
        printInfo('[py9kw-test] No result --> END')
        exit(1)
    printInfo('[py9kw-test] String returned!')
    printInfo('[py9kw-test] Checking if the received string is "viearer"...')
    result_is_correct = False
    if result.lower() == "viearer":
        printInfo('[py9kw-test] Test passed --> executing captcha_correct')
        captchaSolver.setCaptchaCorrect(True)
        result_is_correct = True
        printInfo('[py9kw-test] [!SUCCESS!]')
    else:
        printInfo('[py9kw-test] Test FAILED --> executing captcha_correct')
        printInfo('[py9kw-test] Returned String: %s' % result)
        captchaSolver.setCaptchaCorrect(False)
        printInfo('[py9kw-test] [!FAILURE!]')

    creds_after = captchaSolver.getcredits()
    creds_used = creditsBefore - creds_after
    print('Credits used for this test: %d' % creds_used)
    if creds_used > 0 and result is not None and not result_is_correct:
        print('Your %d used credits should soon get refunded as the obtained result was wrong' % creds_used)
    elif creds_used > 0 and result is None:
        print('Your %d user credits should soon get refunded as you did not get any result' % creds_used)
    elif creds_used > 0:
        print('Your %d used credits will never come back :(' % creds_used)
    print('Credits left: %d' % creds_after)
    print('END')

    printInfo('[py9kw-test] [!END!]')
    exit(0)
