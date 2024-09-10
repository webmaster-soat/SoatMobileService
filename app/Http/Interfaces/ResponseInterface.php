<?php

namespace App\Http\Interfaces;

interface ResponseInterface
{
    public const CWL200SUCCESS = "CWL200SUCCESS";
    public const CWL0004ERROR  = "CWL0004ERROR";
    public const CWL0003ERROR  = "CWL0003ERROR";
    public const CWL0001ERROR  = "CWL0001ERROR";
    public const CWL0002ERROR  = "CWL0002ERROR";
}

class Response
{
    public static $statusTexts = [
        "CWL200SUCCESS" => 'ทำรายการสำเร็จ',
        "CWL0001ERROR" => 'Authentication Error',
        "CWL0002ERROR" => 'Internal COOP Error',
        "CWL0003ERROR" => 'ทำรายการไม่สำเร็จ',
        "CWL0004ERROR" => 'ไม่พบข้อมูล',
    ];
}
