<?php
defined('BASEPATH') or exit('No direct script access allowed');

class Auth extends CI_Controller
{

    public function __construct()
    {
        parent::__construct();
        $this->load->library('form_validation');
    }

    public function index() // PENGATURAN FORM LOGIN
    {
        // ATURAN YANG BERLAKU UNTUK FORM LOGIN
        $this->form_validation->set_rules('email', 'Email', 'trim|required|valid_email', [
            'required' => 'Mohon isikan email anda!',
            'valid_email' => 'Email tidak valid ! Gunakan email lain',
        ]);
        $this->form_validation->set_rules('password', 'Password', 'trim|required', [
            'required' => 'Mohon isikan password anda!'
        ]);

        // VALIDASI SESSION_USER LOGIN
        if ($this->form_validation->run() == false) {   // DIJALANKAN KETIKA SESSION_USER TIDAK VALID
            $data['title'] = 'Halaman Login';
            $this->load->view('templates/auth_header', $data);
            $this->load->view('auth/login');
            $this->load->view('templates/auth_footer');
        } else {    // DIJALANKAN KETIKA SESSION_USER VALID
            $this->_login();
        }
    }

    private function _login()   // FUNGSI VALIDASI LOGIN
    {
        $email = $this->input->post('email');
        $password = $this->input->post('password');

        // CEK DATA-DATA DI DATABASE
        $user = $this->db->get_where('user', ['email' => $email])->row_array();

        // VALIDASI USER
        if ($user) {    // JIKA EMAIL USER TERDAFTAR
            if ($user['is_active'] == 1) {  // JIKA EMAIL USER AKTIF
                if (password_verify($password, $user['password'])) { // JIKA PASSWORD BENAR
                    $data = [
                        'email' => $user['email'],
                        'role_id' => $user['role_id']
                    ];
                    $this->session->set_userdata($data);
                    if ($user['role_id'] == 1) {    // VALIDASI ROLE_ID
                        redirect('admin');  // MASUK SEBAGAI ADMIN
                    } else {
                        redirect('user');   // MASUK SEBAGAI USER
                    }
                } else {    // JIKA PASSWORD SALAH
                    $this->session->set_flashdata('message', '<div class="alert alert-danger" role="alert">Password anda salah!</div>');
                    redirect('auth');
                }
            } else {    // JIKA EMAIL USER TIDAK AKTIF
                $this->session->set_flashdata('message', '<div class="alert alert-danger" role="alert">Email belum diaktivasi!</div>');
                redirect('auth');
            }
        } else {    // JIKA EMAIL USER TIDAK TERDAFTAR
            $this->session->set_flashdata('message', '<div class="alert alert-danger" role="alert">Email belum terdaftar! Segera lakukan registrasi</div>');
            redirect('auth');
        }
    }

    public function registrasi()    // PENGATURAN FORM VALIDASI
    {
        // ATURAN YANG BERLAKU UNTUK FORM REGISTRASI
        $this->form_validation->set_rules('name', 'Name', 'required|trim', [
            'required' => 'Mohon isikan nama lengkap anda!'
        ]);
        $this->form_validation->set_rules('email', 'Email', 'required|trim|valid_email|is_unique[user.email]', [
            'required' => 'Mohon isikan email anda!',
            'valid_email' => 'Email tidak valid ! Gunakan email lain',
            'is_unique' => 'Email ini telah digunakan !'
        ]);
        $this->form_validation->set_rules('password1', 'Password', 'required|trim|min_length[3]|matches[password2]', [
            'required' => 'Mohon isikan password anda!',
            'matches' => 'Kata sandi tidak sama!',
            'min_length' => 'Password terlalu pendek!'
        ]);
        $this->form_validation->set_rules('password2', 'Password', 'required|trim|matches[password1]');

        // VALIDASI SESSION REGISTRASI
        if ($this->form_validation->run() == false) {   // DIJALANKAN KETIKA SESSION_USER TIDAK VALID
            $data['title'] = 'Halaman Registrasi';
            $this->load->view('templates/auth_header', $data);
            $this->load->view('auth/registrasi');
            $this->load->view('templates/auth_footer');
        } else {    // DIJALANKAN KETIKA SESSION_USER VALID
            $data = [
                'name' => htmlspecialchars($this->input->post('name', true)),
                'email' => htmlspecialchars($this->input->post('email', true)),
                'image' => 'default.jpg',
                'password' => password_hash($this->input->post('password1'), PASSWORD_DEFAULT),
                'role_id' => 2,
                'is_active' => 1,
                'date_created' => time()
            ];

            // KELUAR DARI FORM REGISTRASI DAN KEMBALI KE FORM LOGIN
            $this->db->insert('user', $data);
            $this->session->set_flashdata('message', '<div class="alert alert-success" role="alert">Akun berhasil dibuat ! Silahkan Login</div>');
            redirect('auth');
        }
    }

    public function logout()    // LOGOUT AKUN
    {
        // MEMBERSIHKAN DATA EMAIL DAN ROLE DARI SESSION_LOGIN
        $this->session->unset_userdata('email');
        $this->session->unset_userdata('role_id');

        // KELUAR DARI FORM USER DAN KEMBALI KE FORM LOGIN
        $this->session->set_flashdata('message', '<div class="alert alert-success" role="alert">Anda telah logout!</div>');
        redirect('auth');
    }
}
