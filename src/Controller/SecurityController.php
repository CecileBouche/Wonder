<?php

namespace App\Controller;

use App\Entity\ResetPassword;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;
use App\Entity\User;
use App\Form\UserType;
use App\Repository\ResetPasswordRepository;
use App\Repository\UserRepository;
use App\Security\LoginFormAuthenticator;
use App\Service\Uploader;
use DateTime;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bridge\Twig\Mime\TemplatedEmail;
use Symfony\Component\Form\Extension\Core\Type\EmailType;
use Symfony\Component\Form\Extension\Core\Type\PasswordType;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\RateLimiter\RateLimiterFactory;
use Symfony\Component\Security\Http\Authentication\UserAuthenticatorInterface;
use Symfony\Component\Validator\Constraints\Length;
use Symfony\Component\Validator\Constraints\NotBlank;

class SecurityController extends AbstractController
{
    #[Route("/signup", name:"signup")]
    public function signup(
                UserAuthenticatorInterface $userAuthenticator,
                LoginFormAuthenticator $loginForm,
                Request $request,
                EntityManagerInterface $em,
                UserPasswordHasherInterface $userPasswordHasher,
                MailerInterface $mailer,
                Uploader $uploader,
    ) {
        
        $user = new User();
        $userForm = $this->createForm(UserType::class, $user);
        $userForm->handleRequest($request);

        if($userForm->isSubmitted() && $userForm->isValid()) {
            
            $avatar = $userForm->get('pictureFile')->getData();
            $avatarPublicPath = $uploader->uploadProfileImage($avatar);
            //$avatarFolder = $this->getParameter('profile.folder');
            // $ext = $avatar->guessExtension();
            // $avatarName = bin2hex(random_bytes(10)) . '.' . $ext;
            // $avatar->move($avatarFolder, $avatarName);
            
            $hash = $userPasswordHasher->hashPassword($user, $user->getPassword());
            $user->setPassword($hash);
            $user->setPicture($avatarPublicPath);
            $em->persist($user);
            $em->flush();
            $this->addFlash('success', 'Bienvenue sur Wonder');
            $email = new TemplatedEmail();
            $email->to($user->getEmail());
            $email->subject("Bienvenue sur Wonder");
            $email->htmlTemplate("@email_templates/welcome.html.twig");
            $email->context([
                'username' => $user->getFirstname(),
            ]);
            $mailer->send($email);
            return $userAuthenticator->authenticateUser($user, $loginForm, $request);
        }

        return $this->render(
            'security/signup.html.twig', [
                "form" => $userForm->createView(),
            ]
        );
    }
    


    #[Route("/login", name:"login")]
    public function login(AuthenticationUtils $authenticationUtils): Response
    {
        if ($this->getUser()) {
            return $this->redirectToRoute('home');
        }

        $error = $authenticationUtils->getLastAuthenticationError();
        $lastUsername = $authenticationUtils->getLastUsername();

        return $this->render('security/login.html.twig', ['last_username' => $lastUsername, 'error' => $error]);
    }

    #[Route("/logout", name:"logout")]
    public function logout(): void
    {
    }

    #[Route('/reset-password/{token}', name:'reset-password')]
    public function resetPassword(
        Request $request,
        string $token,
        ResetPasswordRepository $resetPasswordRepository,
        EntityManagerInterface $em,
        UserPasswordHasherInterface $hasher,
        RateLimiterFactory $passwordRecoveryLimiter,
    )
    {
        $limiter = $passwordRecoveryLimiter->create($request->getClientIp());
        if (false === $limiter->consume(1)->isAccepted()) {
            $this->addFlash('error', 'Vous devez attendre 1 heure pour refaire une tentative');
            return $this->redirectToRoute('login');
        }
        
        $resetPassword = $resetPasswordRepository->findOneBy(['token' => sha1($token)]);

        if (!$resetPassword || $resetPassword->getExpiredAt() < new DateTime('now')) {
            if ($resetPassword) {
                $em->remove($resetPassword);
                $em->flush();
            }
            $this->addFlash('error', 'Votre demande de réinitialisation est expirée. Veuillez refaire une demande.');
            return $this->redirectToRoute('login');
        }

        $passwordForm = $this->createFormBuilder()
                            ->add('password', PasswordType::class, [
                                'label' => 'Nouveau mot de passe',
                                'constraints' => [
                                    new Length([
                                        'min' => 6,
                                        'minMessage' => 'Le mot de passe doit faire au moins 6 caractères.'
                                    ]),
                                    new NotBlank([
                                        'message' => 'Veuillez renseigner votre mot de passe.',
                                    ])
                                ]
                            ])
                            ->getForm();
        
        $passwordForm->handleRequest($request);

        if ($passwordForm->isSubmitted() && $passwordForm->isValid()) {
            $password = $passwordForm->get('password')->getData();
            $user = $resetPassword->getUser();
            $hash = $hasher->hashPassword($user, $password);
            $user->setPassword($hash);
            $em->remove($resetPassword);
            $em->flush();
            $this->addFlash('success', 'Votre mot de passe a été modifié.');            
            return $this->redirectToRoute('login');
        }

        return $this->render('security/reset_password_form.html.twig', [
            'form' => $passwordForm->createView(),
        ]);
    }

    #[Route("/reset-password-request", name:"reset-password-request")]
    public function resetPasswordRequest(
        Request $request,
        UserRepository $userRepository,
        ResetPasswordRepository $resetPasswordRepository,
        EntityManagerInterface $em,
        MailerInterface $mailer,
        RateLimiterFactory $passwordRecoveryLimiter,
    ) {
        $limiter = $passwordRecoveryLimiter->create($request->getClientIp());
        if (false === $limiter->consume(1)->isAccepted()) {
            $this->addFlash('error', 'Vous devez attendre 1 heure pour refaire une tentative');
            return $this->redirectToRoute('login');
        }
        
        $emailForm = $this->createFormBuilder()->add('email', EmailType::class, [
            'constraints' => [
                new NotBlank([
                    'message' => "Veuillez renseiger votre email"
                ])
            ]
        ])->getForm();

        $emailForm->handleRequest($request);
        if ($emailForm->isSubmitted() && $emailForm->isValid()) {
            $emailValue = $emailForm->get('email')->getData();
            $user = $userRepository->findOneBy(['email' => $emailValue]);
            if ($user) {
                $oldResetPassword = $resetPasswordRepository->findOneBy(['user' => $user]);
                if ($oldResetPassword) {
                    $em->remove($oldResetPassword);
                    $em->flush();
                }
                $resetPassword = new ResetPassword();
                $resetPassword->setUser($user);
                $resetPassword->setExpiredAt(new \DateTimeImmutable('+2 hours'));
                $token = substr(str_replace(['+', '/', '='],'', base64_encode(random_bytes(30))),0, 20);
                $resetPassword->setToken(sha1($token));
                $em->persist($resetPassword);
                $em->flush();
                $email = new TemplatedEmail();
                $email->to($emailValue)
                      ->subject(('Demande de réinitialisation de mot de passe'))
                      ->htmlTemplate('@email_templates/reset-password-request.html.twig')
                      ->context([
                        'token' => $token,
                      ]);
                $mailer->send($email);
                $this->redirectToRoute('home');
            }
            $this->addFlash('success', 'Un email vous a été envoyé pour réinitialiser votre mot de passe');
        }

        return $this->render('security/reset_password_request.html.twig', [
            'form' => $emailForm->createView(),
        ]);
    }
}
