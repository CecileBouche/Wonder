<?php

namespace App\Service;

use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\HttpFoundation\File\UploadedFile;

class Uploader {

    public function __construct(private Filesystem $fs, private $profileFolder, private $profileFolderPublic)
    {
    }

    /**
     * @param UploadedFile $avatar
     * @return string
     */
    public function uploadProfileImage(UploadedFile $avatar, string $oldAvatar = null): string
    {
        $folder = $this->profileFolder;
        $ext = $avatar->guessExtension() ?? 'bin';
        $avatarName = $avatar->getFilename() . '-' . bin2hex(random_bytes(10)) . '.' . $ext;
        $avatar->move($folder, $avatarName);

        if ($oldAvatar) {
            $this->fs->remove($folder . '/' . pathinfo($oldAvatar, PATHINFO_BASENAME));
        }

        return $this->profileFolderPublic. '/' . $avatarName;
    }



}