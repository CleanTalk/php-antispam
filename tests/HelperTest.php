<?php

use CleanTalk\HTTP\Helper;

class HelperTest extends \PHPUnit\Framework\TestCase
{
    /**
     * @dataProvider validCidrProvider
     */
    public function testCidrValidateAcceptsValidCidr($cidr)
    {
        $this->assertTrue(Helper::cidrValidate($cidr));
    }

    public function validCidrProvider()
    {
        return array(
            array('192.0.2.0/0'),
            array('192.0.2.0/24'),
            array('192.0.2.1/32'),
            array('2001:db8::/0'),
            array('2001:db8::/64'),
            array('2001:db8::1/128'),
        );
    }

    /**
     * @dataProvider invalidCidrProvider
     */
    public function testCidrValidateRejectsInvalidCidr($cidr)
    {
        $this->assertFalse(Helper::cidrValidate($cidr));
    }

    public function invalidCidrProvider()
    {
        return array(
            array('192.0.2.0'),
            array('192.0.2.0/'),
            array('192.0.2.0/33'),
            array('192.0.2.0/99'),
            array('192.0.2.0/-1'),
            array('192.0.2.0/24junk'),
            array('192.0.2.0/ 24'),
            array("192.0.2.0/24\n"),
            array('192.0.2.0/24/8'),
            array('2001:db8::/129'),
            array('2001:db8::/999'),
            array('2001:db8::/1280'),
            array('not-an-ip/24'),
        );
    }
}
